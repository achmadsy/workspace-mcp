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
	"log/slog"
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

// selfTestScript runs inside the sandbox at startup. It checks isolation
// properties rather than only proving that a process can start. Each failing
// check has its own exit code so the startup error is actionable.
const selfTestScript = `test -d /workspace && test -w /workspace || exit 11
test ! -e /root || exit 12
test ! -e /etc/shadow || exit 13
test -z "$(ls -A /home)" || exit 14
test ! -e /run/user || exit 15
test -s /etc/passwd || exit 16
`

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
	testRequest := Request{Script: selfTestScript, TimeoutMS: 4000}
	runSelfTest := func() (Result, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if r.cfg.EnableExec || r.cfg.EnableGitNetwork {
			return r.Run(ctx, testRequest, nil)
		}
		return r.RunIsolated(ctx, testRequest, nil)
	}
	res, err := runSelfTest()
	if err != nil && cfg.SlirpSandbox && shouldRetryWithoutSlirpSandbox(err) {
		initialErr := err
		r.cfg.SlirpSandbox = false
		res, err = runSelfTest()
		if err == nil {
			slog.Warn("slirp4netns sandbox hardening unavailable; continuing with seccomp", "initial_error", initialErr)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("sandbox self-test failed: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("sandbox self-test failed with exit code %d (11 workspace, 12 /root visible, 13 /etc/shadow visible, 14 /home not empty, 15 /run/user visible, 16 /etc/passwd missing): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return r, nil
}

// slirpMountSandboxFailure recognizes the slirp4netns mount-sandbox failure seen
// on WSL2: `setegid(0) ... parent failed`.
func slirpMountSandboxFailure(text string) bool {
	return strings.Contains(text, "setegid(0)") && strings.Contains(text, "parent failed")
}

// slirpNamespaceJoinFailure recognizes slirp4netns failing to enter the
// sandbox's network namespace: `setns(CLONE_NEWNET): Operation not permitted`.
// It succeeds on an immediate retry, so it looks like a startup race.
func slirpNamespaceJoinFailure(text string) bool {
	return strings.Contains(text, "setns(CLONE_NEWNET)") && strings.Contains(text, "Operation not permitted")
}

// shouldRetryWithoutSlirpSandbox reports whether startup may drop the slirp4netns
// mount-sandbox layer. Only the mount-sandbox signature qualifies: a namespace
// join failure says nothing about that layer, so it is retried (see
// isTransientNetworkStartFailure) but never weakens the hardening.
func shouldRetryWithoutSlirpSandbox(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "isolated network helper") && slirpMountSandboxFailure(message)
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
	hasSSH := credentials.SSHKey != nil || credentials.KnownHosts != nil
	hasHTTPS := credentials.HTTPSToken != nil
	if hasSSH && hasHTTPS {
		return Result{}, errors.New("provide exactly one Git credential mode")
	}
	if (credentials.SSHKey == nil) != (credentials.KnownHosts == nil) {
		return Result{}, errors.New("SSH key and known_hosts must be provided together")
	}
	out := &limitBuffer{limit: r.cfg.ExecMaxOutput, mode: bufferHeadTail}
	errOut := &limitBuffer{limit: r.cfg.ExecMaxOutput, mode: bufferHeadTail}
	return r.runWithBuffersAndCredentials(ctx, request, extraEnv, true, out, errOut, nil, credentials)
}

func (r *Runner) run(ctx context.Context, request Request, extraEnv map[string]string, network bool) (Result, error) {
	// Synchronous runs keep the head and the tail of each stream: build and test
	// failures are normally reported at the end of the output.
	out := &limitBuffer{limit: r.cfg.ExecMaxOutput, mode: bufferHeadTail}
	errOut := &limitBuffer{limit: r.cfg.ExecMaxOutput, mode: bufferHeadTail}
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
	cmd, unit := r.systemdCommand(runCtx, args, rootFile, statusWriter, blockReader, secretFiles, out, errOut)
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
			r.killUnit(unit)
			<-commandDone
			return Result{}, annotateSandboxError(err, runErr, errOut)
		}
	} else {
		runErr = <-commandDone
	}
	if runCtx.Err() != nil {
		// Timeout or cancellation: make sure nothing survives in the scope.
		r.killUnit(unit)
	}
	return commandResult(runCtx, cmd, runErr, startedAt, out, errOut), nil
}

// killUnit is a best-effort backstop that kills every process in a sandbox
// scope. Process-group and PID-namespace teardown normally suffice; this covers
// helpers that escape the process group. Errors are ignored because the scope
// usually no longer exists.
func (r *Runner) killUnit(unit string) {
	if r.cfg.SystemctlPath == "" || unit == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.cfg.SystemctlPath, "--user", "kill", "--signal=SIGKILL", unit+".scope")
	cmd.Env = systemdClientEnv()
	_ = cmd.Run()
}

// systemdClientEnv is the environment for systemd client tools. It stays minimal
// but must carry the location of the user manager's bus, which holds no secret.
func systemdClientEnv() []string {
	env := buildEnvironment(nil, nil)
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		candidate := "/run/user/" + strconv.Itoa(os.Getuid())
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			runtimeDir = candidate
		}
	}
	if runtimeDir != "" {
		env = append(env, "XDG_RUNTIME_DIR="+runtimeDir)
	}
	if bus := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); bus != "" {
		env = append(env, "DBUS_SESSION_BUS_ADDRESS="+bus)
	}
	return env
}

func (r *Runner) systemdCommand(ctx context.Context, sandboxArgs []string, rootFile, statusWriter, blockReader *os.File, secretFiles []*os.File, out, errOut io.Writer) (*exec.Cmd, string) {
	unit := randomUnit()
	systemdArgs := []string{
		"--user", "--scope", "--quiet", "--collect",
		"--unit=" + unit,
		"--property=MemoryMax=" + strconv.FormatUint(r.cfg.ExecMemoryBytes, 10),
		"--property=MemorySwapMax=0",
		"--property=TasksMax=" + strconv.FormatUint(r.cfg.ExecMaxProcesses, 10),
		"--property=CPUQuota=100%",
		"--",
		r.cfg.PrlimitPath,
		"--cpu=" + strconv.FormatUint(r.cfg.ExecCPUSeconds, 10),
		"--nofile=" + strconv.FormatUint(r.cfg.ExecMaxOpenFiles, 10),
	}
	// Deliberately no --as (virtual address space; Go, Node and the JVM reserve far
	// more than they use) and no --nproc (counted per real UID, including the
	// server itself). Memory and task limits are enforced by the cgroup scope.
	if r.cfg.ExecMaxFileBytes > 0 {
		systemdArgs = append(systemdArgs, "--fsize="+strconv.FormatUint(r.cfg.ExecMaxFileBytes, 10))
	}
	systemdArgs = append(systemdArgs, "--")
	systemdArgs = append(systemdArgs, sandboxArgs...)
	cmd := exec.CommandContext(ctx, r.cfg.SystemdRunPath, systemdArgs...)
	cmd.ExtraFiles = []*os.File{rootFile}
	if statusWriter != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, statusWriter, blockReader)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, secretFiles...)
	cmd.Env = systemdClientEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		cancelProcessGroup(cmd)
		go r.killUnit(unit)
		return nil
	}
	cmd.WaitDelay = time.Second
	cmd.Stdout, cmd.Stderr = out, errOut
	return cmd, unit
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

	started := r.startNetworkWithRetry(ctx, cmd, childPID, commandDone, errOut)
	if started.network == nil {
		// Helper failure (err), sandbox exit (runErr and err), or context end
		// while starting (runErr only).
		return started.runErr, started.err
	}
	network := started.network
	defer network.stop()

	if _, err := blockWriter.Write([]byte{1}); err != nil {
		return nil, errors.New("sandbox startup synchronization failed")
	}
	_ = blockWriter.Close()

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

const (
	networkStartAttempts     = 5
	networkStartBackoff      = 50 * time.Millisecond
	networkHelperStderrLimit = 4096
)

// isTransientNetworkStartFailure recognizes the intermittent slirp4netns start
// failures seen on WSL2 (an allowlist of known signatures), which are retried
// with the same hardening instead of weakening it. Unrelated failures are not
// retried.
func isTransientNetworkStartFailure(helperStderr string) bool {
	return slirpMountSandboxFailure(helperStderr) || slirpNamespaceJoinFailure(helperStderr)
}

// networkStartResult is the outcome of startNetworkWithRetry.
type networkStartResult struct {
	network *networkProcess
	runErr  error
	err     error
}

// startNetworkWithRetry starts the slirp4netns helper for the (still blocked)
// sandbox child and waits until it is ready. A known transient start failure is
// retried a bounded number of times; the sandbox stays blocked on its block-fd
// the whole time, so a retry exposes nothing. Helper stderr is captured per
// attempt and only added to errOut when the final attempt fails, so a recovered
// retry leaves no stale error text in the command's own stderr.
//
// The result has network set when the helper is ready. Otherwise runErr holds
// the sandbox exit status when it exited (err is set too) or the context ended
// (err is nil), and err alone means the helper failed for good.
func (r *Runner) startNetworkWithRetry(ctx context.Context, cmd *exec.Cmd, childPID int, commandDone <-chan error, errOut *limitBuffer) networkStartResult {
	for attempt := 1; ; attempt++ {
		helperErr := &limitBuffer{limit: networkHelperStderrLimit}
		network, err := r.startNetwork(ctx, childPID, helperErr)
		if err != nil {
			return networkStartResult{err: err}
		}
		var failure error
		select {
		case readyOK := <-network.ready:
			if readyOK {
				if attempt > 1 {
					slog.Info("slirp4netns started after retry", "attempts", attempt)
				}
				return networkStartResult{network: network}
			}
			failure = errors.New("isolated network helper closed its readiness pipe")
		case doneErr := <-network.done:
			if doneErr == nil {
				failure = errors.New("isolated network helper exited before readiness")
			} else {
				failure = fmt.Errorf("isolated network helper exited before readiness: %w", doneErr)
			}
		case runErr := <-commandDone:
			network.stop()
			return networkStartResult{runErr: runErr, err: errors.New("sandbox exited before network became ready")}
		case <-ctx.Done():
			network.stop()
			cancelProcessGroup(cmd)
			return networkStartResult{runErr: <-commandDone}
		}
		// stop waits for the helper to exit, so its stderr is complete below.
		network.stop()
		stderrText := helperErr.String()
		if attempt >= networkStartAttempts || !isTransientNetworkStartFailure(stderrText) {
			_, _ = errOut.Write([]byte(stderrText))
			if attempt > 1 {
				failure = fmt.Errorf("%w (after %d attempts)", failure, attempt)
			}
			return networkStartResult{err: failure}
		}
		slog.Warn("slirp4netns start failed with a known transient error; retrying",
			"attempt", attempt, "of", networkStartAttempts, "helper_stderr", strings.TrimSpace(stderrText))
		select {
		case <-time.After(time.Duration(attempt) * networkStartBackoff):
		case runErr := <-commandDone:
			return networkStartResult{runErr: runErr, err: errors.New("sandbox exited before network became ready")}
		case <-ctx.Done():
			cancelProcessGroup(cmd)
			return networkStartResult{runErr: <-commandDone}
		}
	}
}

func (r *Runner) commandArgs(request Request, extraEnv map[string]string, network bool, credentials GitCredentialFiles) ([]string, []*os.File, []*os.File, error) {
	cwd := "/workspace"
	if request.Cwd != "" {
		cwd += "/" + request.Cwd
	}
	args := []string{
		r.cfg.BwrapPath,
		"--die-with-parent", "--new-session", "--unshare-all", "--cap-drop", "ALL",
	}
	if r.cfg.ExecDisableUserns {
		// Forbid nested user namespaces inside the sandbox (reduces kernel attack
		// surface). Enabled only when the installed bubblewrap supports it.
		args = append(args, "--unshare-user", "--disable-userns")
	}
	args = append(args,
		"--ro-bind", "/usr", "/usr",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--dir", "/etc",
		"--ro-bind-try", "/etc/ssl/certs", "/etc/ssl/certs",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home",
		"--bind-fd", strconv.Itoa(workspaceFD), "/workspace", "--chdir", cwd,
	)
	if network {
		if r.cfg.Slirp4netnsPath == "" {
			return nil, nil, nil, errors.New("isolated network helper is unavailable")
		}
		args = append(args,
			"--json-status-fd", strconv.Itoa(statusFD),
			"--block-fd", strconv.Itoa(blockFD),
		)
	}
	secretFiles := make([]*os.File, 0, 8)
	generatedFiles := make([]*os.File, 0, 6)
	// Descriptors after the workspace root (and, with networking, the status and
	// block pipes) are the files appended to secretFiles, in order.
	fdBase := workspaceFD + 1
	if network {
		fdBase = secretFD
	}
	nextFD := fdBase
	switch {
	case credentials.SSHKey != nil:
		keyFD := strconv.Itoa(nextFD)
		secretFiles = append(secretFiles, credentials.SSHKey)
		nextFD++
		knownHostsFD := strconv.Itoa(nextFD)
		secretFiles = append(secretFiles, credentials.KnownHosts)
		args = append(args,
			"--dir", "/run", "--dir", "/run/workspace-mcp",
			"--perms", "0400", "--ro-bind-data", keyFD, "/run/workspace-mcp/id",
			"--perms", "0444", "--ro-bind-data", knownHostsFD, "/run/workspace-mcp/known_hosts",
		)
		extraEnv = cloneEnvironment(extraEnv)
		extraEnv["GIT_SSH_COMMAND"] = "/usr/bin/ssh -i /run/workspace-mcp/id -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/workspace-mcp/known_hosts -o GlobalKnownHostsFile=/dev/null -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o BatchMode=yes"
	case credentials.HTTPSToken != nil:
		help, err := anonymousFile("git-askpass", []byte("#!/bin/sh\ncase $1 in\n*Username*) printf '%s\\n' oauth2 ;;\n*Password*) cat \"$MCP_ASKPASS_TOKEN_FILE\" ;;\n*) exit 1 ;;\nesac\n"))
		if err != nil {
			return nil, nil, nil, errors.New("create HTTPS credential helper")
		}
		generatedFiles = append(generatedFiles, help)
		helpFD := strconv.Itoa(nextFD)
		secretFiles = append(secretFiles, help)
		nextFD++
		tokenFD := strconv.Itoa(nextFD)
		secretFiles = append(secretFiles, credentials.HTTPSToken)
		args = append(args,
			"--dir", "/run", "--dir", "/run/workspace-mcp",
			"--perms", "0500", "--ro-bind-data", helpFD, "/run/workspace-mcp/askpass",
			"--perms", "0400", "--ro-bind-data", tokenFD, "/run/workspace-mcp/token",
		)
		extraEnv = cloneEnvironment(extraEnv)
		extraEnv["GIT_ASKPASS"] = "/run/workspace-mcp/askpass"
		extraEnv["MCP_ASKPASS_TOKEN_FILE"] = "/run/workspace-mcp/token"
	}
	etcArgs, etcFiles, err := syntheticEtc(network, fdBase+len(secretFiles))
	if err != nil {
		closeAll(generatedFiles)
		return nil, nil, nil, errors.New("create sandbox /etc files")
	}
	args = append(args, etcArgs...)
	secretFiles = append(secretFiles, etcFiles...)
	generatedFiles = append(generatedFiles, etcFiles...)
	args = append(args, "--", "/usr/bin/env", "-i")
	args = append(args, buildEnvironment(request.Env, extraEnv)...)
	if request.Script != "" {
		return append(args, "/bin/sh", "-c", request.Script), secretFiles, generatedFiles, nil
	}
	return append(args, request.Argv...), secretFiles, generatedFiles, nil
}

func anonymousFile(name string, content []byte) (*os.File, error) {
	return memFile(name, content, 0o500)
}

// anonymousDataFile creates a read-only data file for non-executable content.
func anonymousDataFile(name string, content []byte) (*os.File, error) {
	return memFile(name, content, 0o444)
}

func memFile(name string, content []byte, mode uint32) (*os.File, error) {
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
	if err := unix.Fchmod(fd, mode); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

type etcEntry struct {
	path    string
	content string
}

// syntheticEtc builds the minimal /etc files as anonymous in-memory files, so
// the sandbox never sees host account data or host resolver configuration. The
// host resolv.conf is deliberately not reused: it commonly points at a loopback
// stub (127.0.0.53) that does not exist inside the private network namespace.
// With networking, slirp4netns serves DNS at 10.0.2.3. passwd and group give
// tools such as ssh an entry for the sandbox user. firstFD is the descriptor
// number the first returned file will have in the child. --ro-bind-data consumes
// the descriptor directly; /proc/self/fd paths cannot represent deleted memfds
// reliably because bubblewrap resolves their magic symlinks before mounting.
func syntheticEtc(network bool, firstFD int) ([]string, []*os.File, error) {
	uid, gid := os.Getuid(), os.Getgid()
	passwd := "root:x:0:0:root:/root:/bin/sh\n"
	if uid != 0 {
		passwd += fmt.Sprintf("sandbox:x:%d:%d:sandbox:/home:/bin/sh\n", uid, gid)
	}
	group := "root:x:0:\n"
	if gid != 0 {
		group += fmt.Sprintf("sandbox:x:%d:\n", gid)
	}
	entries := []etcEntry{
		{path: "/etc/passwd", content: passwd},
		{path: "/etc/group", content: group},
		{path: "/etc/hosts", content: "127.0.0.1 localhost\n::1 localhost\n"},
		{path: "/etc/nsswitch.conf", content: "passwd: files\ngroup: files\nhosts: files dns\n"},
	}
	if network {
		entries = append(entries, etcEntry{path: "/etc/resolv.conf", content: "nameserver 10.0.2.3\n"})
	}
	args := make([]string, 0, len(entries)*3)
	files := make([]*os.File, 0, len(entries))
	for i, entry := range entries {
		file, err := anonymousDataFile("etc", []byte(entry.content))
		if err != nil {
			closeAll(files)
			return nil, nil, err
		}
		files = append(files, file)
		args = append(args, "--perms", "0444", "--ro-bind-data", strconv.Itoa(firstFD+i), entry.path)
	}
	return args, files, nil
}

func closeAll(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
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
	args := []string{"--configure", "--mtu=65520", "--disable-host-loopback"}
	// The helper runs on the host and parses guest traffic, so confine it when the
	// installed slirp4netns supports it (probed at startup).
	if r.cfg.SlirpSandbox {
		args = append(args, "--enable-sandbox")
	}
	if r.cfg.SlirpSeccomp {
		args = append(args, "--enable-seccomp")
	}
	args = append(args, "--ready-fd=3", "--exit-fd=4", strconv.Itoa(childPID), "tap0")
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

// annotateSandboxError adds the sandbox exit status and the tail of its stderr
// (bwrap, systemd-run and slirp4netns messages) to a startup failure. Without it
// a failed handshake only says that something exited, not why.
func annotateSandboxError(err, runErr error, stderr *limitBuffer) error {
	var details []string
	if runErr != nil {
		details = append(details, "exit: "+runErr.Error())
	}
	if text := strings.TrimSpace(stderr.String()); text != "" {
		const maxDetail = 2048
		if len(text) > maxDetail {
			text = "..." + text[len(text)-maxDetail:]
		}
		text = strings.ToValidUTF8(text, "")
		details = append(details, "stderr: "+strings.ReplaceAll(text, "\n", " | "))
	}
	if len(details) == 0 {
		return err
	}
	return fmt.Errorf("%w (%s)", err, strings.Join(details, "; "))
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
	values := map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/home", "TMPDIR": "/tmp", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
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

// bufferMode selects how a limitBuffer retains output beyond its limit.
type bufferMode int

const (
	// bufferHead keeps the first limit bytes. Cursors are offsets into them.
	bufferHead bufferMode = iota
	// bufferHeadTail keeps a quarter of the limit from the start and the rest
	// from the end, with an omission marker between them. Build and test failures
	// are usually reported at the end of the output.
	bufferHeadTail
	// bufferRolling keeps the most recent limit bytes. Cursors are absolute
	// stream offsets, so a poller sees how much was dropped between polls.
	bufferRolling
)

type limitBuffer struct {
	mu        sync.Mutex
	b         bytes.Buffer // retained head (bufferHead, bufferHeadTail) or window (bufferRolling)
	tail      []byte       // bufferHeadTail only
	limit     int
	mode      bufferMode
	dropped   int // bytes omitted from the stream (bufferHeadTail, bufferRolling)
	truncated bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	switch b.mode {
	case bufferHeadTail:
		headLimit := b.limit / 4
		if room := headLimit - b.b.Len(); room > 0 {
			take := min(room, len(p))
			_, _ = b.b.Write(p[:take])
			p = p[take:]
		}
		if len(p) > 0 {
			tailLimit := b.limit - headLimit
			b.tail = append(b.tail, p...)
			if over := len(b.tail) - tailLimit; over > 0 {
				b.tail = b.tail[over:]
				b.dropped += over
				b.truncated = true
			}
		}
	case bufferRolling:
		_, _ = b.b.Write(p)
		if over := b.b.Len() - b.limit; over > 0 {
			b.b.Next(over)
			b.dropped += over
			b.truncated = true
		}
	default:
		remaining := b.limit - b.b.Len()
		if remaining > 0 {
			_, _ = b.b.Write(p[:min(len(p), remaining)])
		}
		if n > remaining {
			b.truncated = true
		}
	}
	return n, nil
}

func (b *limitBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mode == bufferHeadTail {
		if b.dropped == 0 {
			return b.b.String() + string(b.tail)
		}
		return fmt.Sprintf("%s\n[... %d bytes omitted ...]\n%s", b.b.String(), b.dropped, b.tail)
	}
	return b.b.String()
}

// Slice returns retained output from cursor offset, the next cursor, and the
// truncation flag. In bufferRolling mode the cursor is an absolute stream
// offset; an offset older than the retained window resumes at its start.
func (b *limitBuffer) Slice(offset int) (string, int, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data := b.b.Bytes()
	if b.mode == bufferRolling {
		total := b.dropped + len(data)
		if offset < 0 || offset > total {
			return "", total, b.truncated, errors.New("output cursor is outside retained data")
		}
		return string(data[max(0, offset-b.dropped):]), total, b.truncated, nil
	}
	if offset < 0 || offset > len(data) {
		return "", len(data), b.truncated, errors.New("output cursor is outside retained data")
	}
	return string(data[offset:]), len(data), b.truncated, nil
}

// Total reports the absolute stream length: the cursor a reader at the end would hold.
func (b *limitBuffer) Total() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mode == bufferRolling {
		return b.dropped + b.b.Len()
	}
	return b.b.Len()
}

// Dropped reports how many bytes were omitted from the retained output.
func (b *limitBuffer) Dropped() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

func (b *limitBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

var _ io.Writer = (*limitBuffer)(nil)
