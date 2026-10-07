//go:build linux

// Package sandboxexec runs workspace commands inside a fail-closed Linux sandbox.
package sandboxexec

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/config"
	"github.com/link/workspace-mcp/internal/limits"
	"github.com/link/workspace-mcp/internal/workspace"
	"golang.org/x/sys/unix"
)

const (
	workspaceFD = 3
	statusFD    = 4
	blockFD     = 5
	secretFD    = 6
)

// GitCredentialFiles are pre-opened, revalidated credential descriptors for one
// dedicated Git network command. General Run and RunIsolated never accept them.
type GitCredentialFiles struct {
	SSHKey     *os.File
	KnownHosts *os.File
	HTTPSToken *os.File
}

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
	if cfg.BwrapPath == "" || cfg.SystemdRunPath == "" || cfg.PrlimitPath == "" || ((cfg.EnableExec || cfg.EnableGitNetwork) && cfg.Slirp4netnsPath == "") {
		return nil, errors.New("sandbox helpers were not configured")
	}
	r := &Runner{cfg: cfg, root: root, sem: make(chan struct{}, limits.MaxExecConcurrency)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	testRequest := Request{Argv: []string{"/bin/true"}, TimeoutMS: 4000}
	var res Result
	var err error
	if cfg.EnableExec || cfg.EnableGitNetwork {
		res, err = r.Run(ctx, testRequest, nil)
	} else {
		res, err = r.RunIsolated(ctx, testRequest, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("sandbox self-test failed: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("sandbox self-test failed with exit code %d", res.ExitCode)
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

// RunGitNetwork runs one typed Git network command with fixed-purpose credential
// descriptors. Callers must provide either SSHKey+KnownHosts, HTTPSToken, or none.
func (r *Runner) RunGitNetwork(ctx context.Context, request Request, extraEnv map[string]string, credentials GitCredentialFiles) (Result, error) {
	if !r.cfg.EnableGitNetwork {
		return Result{}, errors.New("Git network execution is disabled")
	}
	if (credentials.HTTPSToken != nil) == (credentials.SSHKey != nil || credentials.KnownHosts != nil) && credentials.HTTPSToken != nil {
		return Result{}, errors.New("provide exactly one Git credential mode")
	}
	if (credentials.SSHKey == nil) != (credentials.KnownHosts == nil) {
		return Result{}, errors.New("SSH key and known_hosts must be provided together")
	}
	out := &limitBuffer{limit: r.cfg.ExecMaxOutput}
	errOut := &limitBuffer{limit: r.cfg.ExecMaxOutput}
	return r.runWithBuffersAndCredentials(ctx, request, extraEnv, true, out, errOut, nil, credentials)
}

func (r *Runner) run(ctx context.Context, request Request, extraEnv map[string]string, network bool) (Result, error) {
	out := &limitBuffer{limit: r.cfg.ExecMaxOutput}
	errOut := &limitBuffer{limit: r.cfg.ExecMaxOutput}
	return r.runWithBuffers(ctx, request, extraEnv, network, out, errOut, nil)
}

func (r *Runner) runWithBuffers(ctx context.Context, request Request, extraEnv map[string]string, network bool, out, errOut *limitBuffer, started func()) (Result, error) {
	return r.runWithBuffersAndCredentials(ctx, request, extraEnv, network, out, errOut, started, GitCredentialFiles{})
}

func (r *Runner) runWithBuffersAndCredentials(ctx context.Context, request Request, extraEnv map[string]string, network bool, out, errOut *limitBuffer, started func(), credentials GitCredentialFiles) (Result, error) {
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

	var statusReader, statusWriter, blockReader, blockWriter *os.File
	if network {
		statusReader, statusWriter, err = os.Pipe()
		if err != nil {
			return Result{}, errors.New("sandbox status pipe is unavailable")
		}
		defer statusReader.Close()
		defer statusWriter.Close()
		blockReader, blockWriter, err = os.Pipe()
		if err != nil {
			return Result{}, errors.New("sandbox startup pipe is unavailable")
		}
		defer blockReader.Close()
		defer blockWriter.Close()
	}

	args, secretFiles, generatedFiles, err := r.commandArgs(request, extraEnv, network, credentials)
	if err != nil {
		return Result{}, err
	}
	for _, file := range generatedFiles {
		defer file.Close()
	}
	cmd := r.systemdCommand(runCtx, args, rootFile, statusWriter, blockReader, secretFiles, out, errOut)
	startedAt := time.Now()
	if err := cmd.Start(); err != nil {
		return Result{}, errors.New("sandbox command could not be started")
	}
	if started != nil {
		started()
	}
	if network {
		_ = statusWriter.Close()
		statusWriter = nil
		_ = blockReader.Close()
		blockReader = nil
	}

	commandDone := make(chan error, 1)
	go func() {
		commandDone <- cmd.Wait()
		close(commandDone)
	}()

	var runErr error
	if network {
		runErr, err = r.runNetworkHandshake(runCtx, cmd, commandDone, statusReader, blockWriter, errOut)
		if err != nil {
			cancelProcessGroup(cmd)
			<-commandDone
			return Result{}, err
		}
	} else {
		runErr = <-commandDone
	}
	return commandResult(runCtx, cmd, runErr, startedAt, out, errOut), nil
}

func (r *Runner) systemdCommand(ctx context.Context, sandboxArgs []string, rootFile, statusWriter, blockReader *os.File, secretFiles []*os.File, out, errOut io.Writer) *exec.Cmd {
	unit := randomUnit()
	systemdArgs := []string{
		"--user", "--scope", "--quiet", "--collect",
		"--unit=" + unit,
		"--property=MemoryMax=" + strconv.FormatUint(r.cfg.ExecMemoryBytes, 10),
		"--property=TasksMax=" + strconv.FormatUint(r.cfg.ExecMaxProcesses, 10),
		"--property=CPUQuota=100%",
		"--",
		r.cfg.PrlimitPath,
		"--cpu=" + strconv.FormatUint(r.cfg.ExecCPUSeconds, 10),
		"--as=" + strconv.FormatUint(r.cfg.ExecMemoryBytes, 10),
		"--fsize=" + strconv.Itoa(r.cfg.ExecMaxOutput*2),
		"--nproc=" + strconv.FormatUint(r.cfg.ExecMaxProcesses, 10),
		"--nofile=" + strconv.FormatUint(r.cfg.ExecMaxOpenFiles, 10),
		"--",
	}
	systemdArgs = append(systemdArgs, sandboxArgs...)
	cmd := exec.CommandContext(ctx, r.cfg.SystemdRunPath, systemdArgs...)
	cmd.ExtraFiles = []*os.File{rootFile}
	if statusWriter != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, statusWriter, blockReader)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, secretFiles...)
	cmd.Env = buildEnvironment(nil, nil)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		cancelProcessGroup(cmd)
		return nil
	}
	cmd.WaitDelay = time.Second
	cmd.Stdout, cmd.Stderr = out, errOut
	return cmd
}

func (r *Runner) runNetworkHandshake(ctx context.Context, cmd *exec.Cmd, commandDone <-chan error, statusReader, blockWriter *os.File, errOut *limitBuffer) (error, error) {
	status := make(chan childStatus, 1)
	go readChildStatus(statusReader, status)

	var childPID int
	select {
	case event := <-status:
		if event.err != nil {
			return nil, errors.New("sandbox did not report its network namespace")
		}
		childPID = event.pid
	case runErr := <-commandDone:
		return runErr, errors.New("sandbox exited before network setup")
	case <-ctx.Done():
		cancelProcessGroup(cmd)
		return <-commandDone, nil
	}

	network, err := r.startNetwork(ctx, childPID, errOut)
	if err != nil {
		return nil, err
	}
	defer network.stop()

	select {
	case readyOK := <-network.ready:
		if !readyOK {
			return nil, errors.New("isolated network helper closed its readiness pipe")
		}
		if _, err := blockWriter.Write([]byte{1}); err != nil {
			return nil, errors.New("sandbox startup synchronization failed")
		}
		_ = blockWriter.Close()
	case err := <-network.done:
		if err == nil {
			return nil, errors.New("isolated network helper exited before readiness")
		}
		return nil, fmt.Errorf("isolated network helper exited before readiness: %w", err)
	case runErr := <-commandDone:
		return runErr, errors.New("sandbox exited before network became ready")
	case <-ctx.Done():
		cancelProcessGroup(cmd)
		return <-commandDone, nil
	}

	select {
	case runErr := <-commandDone:
		return runErr, nil
	case err := <-network.done:
		cancelProcessGroup(cmd)
		<-commandDone
		if err == nil {
			return nil, errors.New("isolated network helper exited unexpectedly")
		}
		return nil, fmt.Errorf("isolated network helper exited: %w", err)
	case <-ctx.Done():
		cancelProcessGroup(cmd)
		return <-commandDone, nil
	}
}

func (r *Runner) commandArgs(request Request, extraEnv map[string]string, network bool, credentials GitCredentialFiles) ([]string, []*os.File, []*os.File, error) {
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
		"--bind", "/proc/self/fd/" + strconv.Itoa(workspaceFD), "/workspace", "--chdir", cwd,
	}
	if network {
		if r.cfg.Slirp4netnsPath == "" {
			return nil, nil, nil, errors.New("isolated network helper is unavailable")
		}
		args = append(args,
			"--json-status-fd", strconv.Itoa(statusFD),
			"--block-fd", strconv.Itoa(blockFD),
		)
	}
	secretFiles := make([]*os.File, 0, 2)
	generatedFiles := make([]*os.File, 0, 1)
	nextFD := secretFD
	switch {
	case credentials.SSHKey != nil:
		keySource := "/proc/self/fd/" + strconv.Itoa(nextFD)
		secretFiles = append(secretFiles, credentials.SSHKey)
		nextFD++
		knownHostsSource := "/proc/self/fd/" + strconv.Itoa(nextFD)
		secretFiles = append(secretFiles, credentials.KnownHosts)
		args = append(args,
			"--dir", "/run", "--dir", "/run/workspace-mcp",
			"--ro-bind", keySource, "/run/workspace-mcp/id",
			"--ro-bind", knownHostsSource, "/run/workspace-mcp/known_hosts",
		)
		extraEnv = cloneEnvironment(extraEnv)
		extraEnv["GIT_SSH_COMMAND"] = "/usr/bin/ssh -i /run/workspace-mcp/id -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/workspace-mcp/known_hosts -o GlobalKnownHostsFile=/dev/null -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o BatchMode=yes"
	case credentials.HTTPSToken != nil:
		help, err := anonymousFile("git-askpass", []byte("#!/bin/sh\ncase $1 in\n*Username*) printf '%s\\n' oauth2 ;;\n*Password*) cat \"$MCP_ASKPASS_TOKEN_FILE\" ;;\n*) exit 1 ;;\nesac\n"))
		if err != nil {
			return nil, nil, nil, errors.New("create HTTPS credential helper")
		}
		generatedFiles = append(generatedFiles, help)
		helpSource := "/proc/self/fd/" + strconv.Itoa(nextFD)
		secretFiles = append(secretFiles, help)
		nextFD++
		tokenSource := "/proc/self/fd/" + strconv.Itoa(nextFD)
		secretFiles = append(secretFiles, credentials.HTTPSToken)
		args = append(args,
			"--dir", "/run", "--dir", "/run/workspace-mcp",
			"--ro-bind", helpSource, "/run/workspace-mcp/askpass",
			"--ro-bind", tokenSource, "/run/workspace-mcp/token",
		)
		extraEnv = cloneEnvironment(extraEnv)
		extraEnv["GIT_ASKPASS"] = "/run/workspace-mcp/askpass"
		extraEnv["MCP_ASKPASS_TOKEN_FILE"] = "/run/workspace-mcp/token"
	}
	args = append(args, "--", "/usr/bin/env", "-i")
	args = append(args, buildEnvironment(request.Env, extraEnv)...)
	if request.Script != "" {
		return append(args, "/bin/sh", "-c", request.Script), secretFiles, generatedFiles, nil
	}
	return append(args, request.Argv...), secretFiles, generatedFiles, nil
}

func anonymousFile(name string, content []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if _, err := file.Write(content); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	if err := unix.Fchmod(fd, 0o500); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func cloneEnvironment(source map[string]string) map[string]string {
	result := make(map[string]string, len(source)+2)
	for key, value := range source {
		result[key] = value
	}
	return result
}

type childStatus struct {
	pid int
	err error
}

func readChildStatus(r io.Reader, result chan<- childStatus) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var status struct {
			ChildPID int `json:"child-pid"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &status); err != nil {
			result <- childStatus{err: err}
			return
		}
		if status.ChildPID > 0 {
			result <- childStatus{pid: status.ChildPID}
			return
		}
	}
	if err := scanner.Err(); err != nil {
		result <- childStatus{err: err}
	} else {
		result <- childStatus{err: io.EOF}
	}
}

type networkProcess struct {
	cmd      *exec.Cmd
	ready    <-chan bool
	done     <-chan error
	exit     *os.File
	stopOnce sync.Once
}

func (r *Runner) startNetwork(ctx context.Context, childPID int, errOut io.Writer) (*networkProcess, error) {
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		return nil, errors.New("network readiness pipe is unavailable")
	}
	exitReader, exitWriter, err := os.Pipe()
	if err != nil {
		readyReader.Close()
		readyWriter.Close()
		return nil, errors.New("network lifetime pipe is unavailable")
	}
	args := []string{
		"--configure", "--mtu=65520", "--disable-host-loopback",
		"--ready-fd=3", "--exit-fd=4", strconv.Itoa(childPID), "tap0",
	}
	cmd := exec.CommandContext(ctx, r.cfg.Slirp4netnsPath, args...)
	cmd.ExtraFiles = []*os.File{readyWriter, exitReader}
	cmd.Env = buildEnvironment(nil, nil)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		cancelProcessGroup(cmd)
		return nil
	}
	cmd.WaitDelay = time.Second
	cmd.Stdout = io.Discard
	cmd.Stderr = errOut
	if err := cmd.Start(); err != nil {
		readyReader.Close()
		readyWriter.Close()
		exitReader.Close()
		exitWriter.Close()
		return nil, errors.New("isolated network helper could not be started")
	}
	_ = readyWriter.Close()
	_ = exitReader.Close()
	ready := make(chan bool, 1)
	go func() {
		var b [1]byte
		_, readErr := io.ReadFull(readyReader, b[:])
		_ = readyReader.Close()
		ready <- readErr == nil && b[0] == '1'
		close(ready)
	}()
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		close(done)
	}()
	return &networkProcess{cmd: cmd, ready: ready, done: done, exit: exitWriter}, nil
}

func (n *networkProcess) stop() {
	n.stopOnce.Do(func() {
		_ = n.exit.Close()
		select {
		case <-n.done:
		case <-time.After(time.Second):
			cancelProcessGroup(n.cmd)
			<-n.done
		}
	})
}

func cancelProcessGroup(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

func commandResult(ctx context.Context, cmd *exec.Cmd, runErr error, started time.Time, out, errOut *limitBuffer) Result {
	result := Result{
		Stdout: out.String(), Stderr: errOut.String(), DurationMS: time.Since(started).Milliseconds(),
		StdoutTruncated: out.Truncated(), StderrTruncated: errOut.Truncated(),
	}
	if ctx.Err() != nil {
		result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		result.Canceled = errors.Is(ctx.Err(), context.Canceled)
		result.ExitCode = -1
		return result
	}
	if runErr == nil {
		return result
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			result.Signal = status.Signal().String()
		}
		return result
	}
	result.ExitCode = -1
	return result
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
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(values))
	for _, key := range keys {
		out = append(out, key+"="+values[key])
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

func (b *limitBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func (b *limitBuffer) Slice(offset int) (string, int, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data := b.b.Bytes()
	if offset < 0 || offset > len(data) {
		return "", len(data), b.truncated, errors.New("output cursor is outside retained data")
	}
	return string(data[offset:]), len(data), b.truncated, nil
}

func (b *limitBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

var _ io.Writer = (*limitBuffer)(nil)
