//go:build linux

// Package sandboxexec runs workspace commands inside a fail-closed Linux sandbox.
package sandboxexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/config"
	"github.com/link/workspace-mcp/internal/limits"
	"github.com/link/workspace-mcp/internal/workspace"
)

type Request struct {
	Argv      []string          `json:"argv,omitempty"`
	Script    string            `json:"script,omitempty"`
	Cwd       string            `json:"cwd,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	TimeoutMS int               `json:"timeout_ms,omitempty"`
}

type Result struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	Signal          string `json:"signal,omitempty"`
	DurationMS      int64  `json:"duration_ms"`
	TimedOut        bool   `json:"timed_out"`
	Canceled        bool   `json:"canceled"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

type Runner struct {
	cfg  config.Config
	root *workspace.Root
	sem  chan struct{}
}

func New(cfg config.Config, root *workspace.Root) (*Runner, error) {
	if !cfg.EnableExec && !cfg.EnableGitWrite {
		return nil, nil
	}
	if cfg.BwrapPath == "" || cfg.SystemdRunPath == "" || ((cfg.EnableExec || cfg.EnableGitNetwork) && cfg.Slirp4netnsPath == "") {
		return nil, errors.New("sandbox helpers were not configured")
	}
	r := &Runner{cfg: cfg, root: root, sem: make(chan struct{}, limits.MaxExecConcurrency)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := r.RunIsolated(ctx, Request{Argv: []string{"/bin/true"}, TimeoutMS: 4000}, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, fmt.Errorf("sandbox self-test failed: %w", err)
	}
	return r, nil
}

func (r *Runner) Config() config.Config { return r.cfg }

func (r *Runner) Run(ctx context.Context, request Request, extraEnv map[string]string) (Result, error) {
	return r.run(ctx, request, extraEnv, r.cfg.EnableExec || r.cfg.EnableGitNetwork)
}

// RunIsolated runs without network egress. Git local operations use this path.
func (r *Runner) RunIsolated(ctx context.Context, request Request, extraEnv map[string]string) (Result, error) {
	return r.run(ctx, request, extraEnv, false)
}

func (r *Runner) run(ctx context.Context, request Request, extraEnv map[string]string, network bool) (Result, error) {
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}

	timeout := r.cfg.ExecTimeout
	if request.TimeoutMS > 0 {
		timeout = time.Duration(request.TimeoutMS) * time.Millisecond
		if timeout > r.cfg.ExecJobTimeout {
			return Result{}, errors.New("timeout exceeds configured maximum")
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rootFile, err := r.root.SandboxFile()
	if err != nil {
		return Result{}, errors.New("workspace root is unavailable")
	}
	defer rootFile.Close()

	args, networkCleanup, err := r.commandArgs(runCtx, request, network)
	if err != nil {
		return Result{}, err
	}
	defer networkCleanup()
	unit := randomUnit()
	systemdArgs := []string{
		"--user", "--wait", "--pipe", "--quiet", "--collect",
		"--unit=" + unit,
		"--property=MemoryMax=" + strconv.FormatUint(r.cfg.ExecMemoryBytes, 10),
		"--property=TasksMax=" + strconv.FormatUint(r.cfg.ExecMaxProcesses, 10),
		"--property=CPUQuota=100%",
		"--property=NoNewPrivileges=yes",
		"--",
		"prlimit",
		"--cpu=" + strconv.FormatUint(r.cfg.ExecCPUSeconds, 10),
		"--as=" + strconv.FormatUint(r.cfg.ExecMemoryBytes, 10),
		"--fsize=" + strconv.Itoa(r.cfg.ExecMaxOutput*2),
		"--nproc=" + strconv.FormatUint(r.cfg.ExecMaxProcesses, 10),
		"--nofile=" + strconv.FormatUint(r.cfg.ExecMaxOpenFiles, 10),
		"--",
	}
	systemdArgs = append(systemdArgs, args...)

	cmd := exec.CommandContext(runCtx, r.cfg.SystemdRunPath, systemdArgs...)
	cmd.ExtraFiles = []*os.File{rootFile}
	cmd.Env = buildEnvironment(request.Env, extraEnv)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	out := &limitBuffer{limit: r.cfg.ExecMaxOutput}
	errOut := &limitBuffer{limit: r.cfg.ExecMaxOutput}
	cmd.Stdout, cmd.Stderr = out, errOut
	started := time.Now()
	runErr := cmd.Run()
	result := Result{
		Stdout: out.String(), Stderr: errOut.String(), DurationMS: time.Since(started).Milliseconds(),
		StdoutTruncated: out.truncated, StderrTruncated: errOut.truncated,
	}
	if runCtx.Err() != nil {
		result.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
		result.Canceled = errors.Is(runCtx.Err(), context.Canceled)
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		result.ExitCode = -1
		return result, nil
	}
	if runErr == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			result.Signal = status.Signal().String()
		}
		return result, nil
	}
	return Result{}, errors.New("sandbox command could not be started")
}

func (r *Runner) commandArgs(ctx context.Context, request Request, network bool) ([]string, func(), error) {
	cwd := "/workspace"
	if request.Cwd != "" {
		cwd += "/" + request.Cwd
	}
	args := []string{
		r.cfg.BwrapPath,
		"--die-with-parent", "--new-session", "--unshare-all",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--dir", "/etc",
		"--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
		"--ro-bind-try", "/etc/ssl/certs", "/etc/ssl/certs",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home",
		"--bind", "/proc/self/fd/3", "/workspace", "--chdir", cwd,
	}
	cleanup := func() {}
	if network {
		if r.cfg.Slirp4netnsPath == "" {
			return nil, cleanup, errors.New("isolated network helper is unavailable")
		}
		// Current runner deliberately fails closed until slirp namespace attachment
		// is established by the asynchronous launch handshake.
		return nil, cleanup, errors.New("isolated network setup is unavailable")
	}
	_ = ctx
	if request.Script != "" {
		return append(args, "--", "/bin/sh", "-c", request.Script), cleanup, nil
	}
	return append(args, append([]string{"--"}, request.Argv...)...), cleanup, nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateRequest(r Request) error {
	if (len(r.Argv) == 0) == (r.Script == "") {
		return errors.New("provide exactly one of argv or script")
	}
	if len(r.Argv) > limits.MaxExecArgs || len(r.Script) > limits.MaxExecScriptBytes || !utf8.ValidString(r.Script) || strings.IndexByte(r.Script, 0) >= 0 {
		return errors.New("command input exceeds limits or is invalid")
	}
	total := 0
	for _, arg := range r.Argv {
		total += len(arg)
		if !utf8.ValidString(arg) || strings.IndexByte(arg, 0) >= 0 {
			return errors.New("argv must contain UTF-8 strings without NUL")
		}
	}
	if total > limits.MaxExecArgBytes {
		return errors.New("argv exceeds size limit")
	}
	if err := workspace.ValidatePath(r.Cwd, true); err != nil {
		return err
	}
	if len(r.Env) > limits.MaxExecEnv {
		return errors.New("too many environment variables")
	}
	for key, value := range r.Env {
		if !safeEnvName(key) || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
			return errors.New("unsafe environment variable")
		}
	}
	return nil
}

func safeEnvName(key string) bool {
	upper := strings.ToUpper(key)
	if !envName.MatchString(key) || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "GIT_") || strings.HasPrefix(upper, "SSH_") || strings.HasPrefix(upper, "AWS_") || strings.HasPrefix(upper, "MCP_") {
		return false
	}
	if upper == "ENV" || upper == "BASH_ENV" || upper == "HOME" || upper == "PATH" || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "PASSWORD") || strings.HasSuffix(upper, "_KEY") {
		return false
	}
	return true
}

func buildEnvironment(user, extra map[string]string) []string {
	values := map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/home", "TMPDIR": "/tmp", "LC_ALL": "C", "LANG": "C"}
	for key, value := range user {
		values[key] = value
	}
	for key, value := range extra {
		values[key] = value
	}
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func randomUnit() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "workspace-mcp-" + hex.EncodeToString(b[:])
}

type limitBuffer struct {
	mu        sync.Mutex
	b         bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - b.b.Len()
	if remaining > 0 {
		_, _ = b.b.Write(p[:min(len(p), remaining)])
	}
	if n > remaining {
		b.truncated = true
	}
	return n, nil
}
func (b *limitBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func (b *limitBuffer) Slice(offset int) (string, int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data := b.b.Bytes()
	if offset < 0 || offset > len(data) {
		offset = len(data)
	}
	return string(data[offset:]), len(data), b.truncated
}

var _ io.Writer = (*limitBuffer)(nil)
