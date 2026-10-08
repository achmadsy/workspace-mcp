//go:build linux

package sandboxexec

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/link/workspace-mcp/internal/config"
)

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	valid := Request{Argv: []string{"/bin/true"}, Cwd: "subdir", Env: map[string]string{"FEATURE": "on"}}
	if err := validateRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	cases := []Request{
		{},
		{Argv: []string{"true"}, Script: "true"},
		{Argv: []string{"true"}, Cwd: "../escape"},
		{Argv: []string{"true"}, Env: map[string]string{"API_TOKEN": "secret"}},
		{Argv: []string{"true"}, Env: map[string]string{"LD_PRELOAD": "/tmp/x"}},
	}
	for _, request := range cases {
		if err := validateRequest(request); err == nil {
			t.Errorf("invalid request accepted: %#v", request)
		}
	}
}

func TestCommandArgsBuildsCleanEnvironment(t *testing.T) {
	t.Parallel()

	runner := &Runner{cfg: testConfig()}
	args, _, _, err := runner.commandArgs(
		Request{Argv: []string{"/usr/bin/printf", "%s", "ok"}, Env: map[string]string{"FEATURE": "on"}},
		map[string]string{"GIT_CONFIG_NOSYSTEM": "1"},
		true,
		GitCredentialFiles{},
	)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	for _, want := range []string{
		"--json-status-fd\x004", "--block-fd\x005", "/proc/self/fd/3", "/usr/bin/env\x00-i",
		"FEATURE=on", "GIT_CONFIG_NOSYSTEM=1", "/usr/bin/printf\x00%s\x00ok",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("command args missing %q: %q", want, joined)
		}
	}
}

func TestCommandArgsCredentialMounts(t *testing.T) {
	t.Parallel()

	runner := &Runner{cfg: testConfig()}
	key, err := anonymousFile("key", []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	knownHosts, err := anonymousFile("known-hosts", []byte("host key"))
	if err != nil {
		t.Fatal(err)
	}
	defer knownHosts.Close()
	args, files, generated, err := runner.commandArgs(
		Request{Argv: []string{"/usr/bin/git", "fetch"}}, nil, true,
		GitCredentialFiles{SSHKey: key, KnownHosts: knownHosts},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(generated)
	joined := strings.Join(args, "\x00")
	for _, want := range []string{
		"--ro-bind\x00/proc/self/fd/6\x00/run/workspace-mcp/id",
		"--ro-bind\x00/proc/self/fd/7\x00/run/workspace-mcp/known_hosts",
		"GIT_SSH_COMMAND=/usr/bin/ssh -i /run/workspace-mcp/id",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("SSH args missing %q: %q", want, joined)
		}
	}
	if len(files) != 2+syntheticEtcFiles(true) {
		t.Fatalf("SSH files = %d", len(files))
	}

	token, err := anonymousFile("token", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	args, files, generated, err = runner.commandArgs(
		Request{Argv: []string{"/usr/bin/git", "fetch"}}, nil, true,
		GitCredentialFiles{HTTPSToken: token},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(generated)
	joined = strings.Join(args, "\x00")
	for _, want := range []string{
		"/run/workspace-mcp/askpass", "/run/workspace-mcp/token",
		"GIT_ASKPASS=/run/workspace-mcp/askpass", "MCP_ASKPASS_TOKEN_FILE=/run/workspace-mcp/token",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("HTTPS args missing %q: %q", want, joined)
		}
	}
	if len(files) != 2+syntheticEtcFiles(true) || len(generated) != 1+syntheticEtcFiles(true) {
		t.Fatalf("HTTPS files = %d generated = %d", len(files), len(generated))
	}
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func TestLimitBufferCursorAndTruncation(t *testing.T) {
	t.Parallel()

	buffer := &limitBuffer{limit: 5}
	if n, err := buffer.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	got, next, truncated, err := buffer.Slice(2)
	if err != nil || got != "cde" || next != 5 || !truncated {
		t.Fatalf("Slice = %q, %d, %t, %v", got, next, truncated, err)
	}
	if _, _, _, err := buffer.Slice(6); err == nil {
		t.Fatal("out-of-range cursor accepted")
	}
	if _, _, _, err := buffer.Slice(-1); err == nil {
		t.Fatal("negative cursor accepted")
	}
	if !buffer.Truncated() {
		t.Fatal("expected truncated buffer")
	}
}

func TestSafeEnvNameAndBuildEnvironment(t *testing.T) {
	t.Parallel()

	for _, safe := range []string{"MY_VAR", "APP_ENV", "DEBUG", "LANG_OVERRIDE"} {
		if !safeEnvName(safe) {
			t.Errorf("safe env name rejected: %q", safe)
		}
	}
	for _, unsafe := range []string{
		"123BAD", "BAD-VAR", "LD_PRELOAD", "GIT_DIR", "SSH_AUTH_SOCK",
		"AWS_ACCESS_KEY_ID", "MCP_STATE_DIR", "ENV", "BASH_ENV", "HOME",
		"PATH", "MY_TOKEN", "APP_SECRET", "DB_PASSWORD", "PRIVATE_KEY",
	} {
		if safeEnvName(unsafe) {
			t.Errorf("unsafe env name accepted: %q", unsafe)
		}
	}

	env := buildEnvironment(map[string]string{"CUSTOM": "val"}, map[string]string{"EXTRA": "extra_val"})
	joined := strings.Join(env, " ")
	for _, want := range []string{"CUSTOM=val", "EXTRA=extra_val", "PATH=/usr/bin:/bin", "HOME=/home"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing env var %q: %s", want, joined)
		}
	}
}

func TestRandomUnit(t *testing.T) {
	t.Parallel()

	u1 := randomUnit()
	u2 := randomUnit()
	if !strings.HasPrefix(u1, "workspace-mcp-") || !strings.HasPrefix(u2, "workspace-mcp-") {
		t.Fatalf("unexpected unit prefix: %s, %s", u1, u2)
	}
	if u1 == u2 {
		t.Fatal("randomUnit collided")
	}
}

func TestValidateRequestEdgeCases(t *testing.T) {
	t.Parallel()

	// Script with NUL byte.
	if err := validateRequest(Request{Script: "echo \x00 bad"}); err == nil {
		t.Fatal("script with NUL accepted")
	}
	// Argv with NUL byte.
	if err := validateRequest(Request{Argv: []string{"echo", "bad\x00arg"}}); err == nil {
		t.Fatal("argv with NUL accepted")
	}
	// Env value with NUL byte.
	if err := validateRequest(Request{Argv: []string{"true"}, Env: map[string]string{"VALID": "bad\x00val"}}); err == nil {
		t.Fatal("env with NUL accepted")
	}
}

func testConfig() config.Config {
	return config.Config{
		BwrapPath: "/usr/bin/bwrap", Slirp4netnsPath: "/usr/bin/slirp4netns",
		SystemdRunPath: "/usr/bin/systemd-run", PrlimitPath: "/usr/bin/prlimit",
		ExecTimeout: time.Second, ExecJobTimeout: time.Minute, ExecJobTTL: time.Minute,
		ExecMaxOutput: 1024, ExecMaxJobs: 4, ExecMemoryBytes: 1 << 30,
		ExecCPUSeconds: 60, ExecMaxProcesses: 32, ExecMaxOpenFiles: 128,
		ExecMaxFileBytes: 1 << 30,
	}
}

// syntheticEtcFiles is the number of in-memory /etc files mounted into a sandbox.
func syntheticEtcFiles(network bool) int {
	if network {
		return 5
	}
	return 4
}

func TestCommandArgsHardening(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.ExecDisableUserns = true
	runner := &Runner{cfg: cfg}

	args, files, generated, err := runner.commandArgs(Request{Argv: []string{"/usr/bin/true"}}, nil, true, GitCredentialFiles{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(generated)
	joined := strings.Join(args, "\x00")
	for _, want := range []string{
		"--unshare-all", "--cap-drop\x00ALL", "--unshare-user\x00--disable-userns",
		"--die-with-parent", "--new-session",
		"--ro-bind\x00/proc/self/fd/6\x00/etc/passwd",
		"--ro-bind\x00/proc/self/fd/7\x00/etc/group",
		"--ro-bind\x00/proc/self/fd/10\x00/etc/resolv.conf",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("hardened args missing %q: %q", want, joined)
		}
	}
	for _, unwanted := range []string{
		"--ro-bind-try\x00/etc/resolv.conf", // host resolver config must never be reused
		"--share-net", "/run/workspace-mcp", "GIT_ASKPASS", "GIT_SSH_COMMAND", "MCP_ASKPASS_TOKEN_FILE",
	} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("general execution args must not contain %q: %q", unwanted, joined)
		}
	}
	if len(files) != syntheticEtcFiles(true) {
		t.Fatalf("files = %d", len(files))
	}

	// Without networking the status/block pipes are absent, so /etc files start at fd 4
	// and there is no resolver file.
	args, files, generated, err = runner.commandArgs(Request{Argv: []string{"/usr/bin/true"}}, nil, false, GitCredentialFiles{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(generated)
	joined = strings.Join(args, "\x00")
	if !strings.Contains(joined, "--ro-bind\x00/proc/self/fd/4\x00/etc/passwd") {
		t.Errorf("isolated args do not start /etc files at fd 4: %q", joined)
	}
	for _, unwanted := range []string{"/etc/resolv.conf", "--json-status-fd", "--block-fd"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("isolated args must not contain %q: %q", unwanted, joined)
		}
	}
	if len(files) != syntheticEtcFiles(false) {
		t.Fatalf("isolated files = %d", len(files))
	}

	// Nested user namespaces are only disabled when requested (and supported).
	runner.cfg.ExecDisableUserns = false
	args, _, generated, err = runner.commandArgs(Request{Argv: []string{"/usr/bin/true"}}, nil, false, GitCredentialFiles{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(generated)
	if joined = strings.Join(args, "\x00"); strings.Contains(joined, "--disable-userns") {
		t.Errorf("--disable-userns present although disabled: %q", joined)
	}
}

func TestSystemdCommandLimits(t *testing.T) {
	t.Parallel()

	runner := &Runner{cfg: testConfig()}
	cmd, unit := runner.systemdCommand(context.Background(), []string{"/usr/bin/bwrap"}, os.Stdin, nil, nil, nil, io.Discard, io.Discard)
	if !strings.HasPrefix(unit, "workspace-mcp-") {
		t.Fatalf("unit = %q", unit)
	}
	joined := strings.Join(cmd.Args, "\x00")
	for _, want := range []string{
		"--property=MemoryMax=1073741824", "--property=MemorySwapMax=0", "--property=TasksMax=32",
		"--cpu=60", "--nofile=128", "--fsize=1073741824",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("systemd args missing %q: %q", want, joined)
		}
	}
	// The file-size limit must not be derived from the output limit (1024 here),
	// and address-space / per-UID process limits must not be applied.
	for _, unwanted := range []string{"--as=", "--nproc=", "--fsize=2048"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("systemd args must not contain %q: %q", unwanted, joined)
		}
	}
}

func TestLimitBufferHeadTail(t *testing.T) {
	t.Parallel()

	buffer := &limitBuffer{limit: 40, mode: bufferHeadTail}
	if n, err := buffer.Write([]byte(strings.Repeat("a", 10))); err != nil || n != 10 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if got := buffer.String(); got != strings.Repeat("a", 10) || buffer.Truncated() {
		t.Fatalf("short output altered: %q truncated=%t", got, buffer.Truncated())
	}
	_, _ = buffer.Write([]byte(strings.Repeat("b", 100)))
	_, _ = buffer.Write([]byte("END"))
	got := buffer.String()
	if !buffer.Truncated() || buffer.Dropped() == 0 {
		t.Fatal("overflow must report truncation and dropped bytes")
	}
	if !strings.HasPrefix(got, strings.Repeat("a", 10)) {
		t.Errorf("head not retained: %q", got)
	}
	if !strings.HasSuffix(got, "bbbEND") {
		t.Errorf("tail not retained: %q", got)
	}
	if !strings.Contains(got, "bytes omitted") {
		t.Errorf("missing omission marker: %q", got)
	}
	// Retained payload (excluding the marker) never exceeds the limit.
	if retained := buffer.b.Len() + len(buffer.tail); retained > 40 {
		t.Errorf("retained %d bytes, limit 40", retained)
	}
}

func TestLimitBufferRollingCursors(t *testing.T) {
	t.Parallel()

	buffer := &limitBuffer{limit: 5, mode: bufferRolling}
	_, _ = buffer.Write([]byte("abc"))
	got, next, truncated, err := buffer.Slice(0)
	if err != nil || got != "abc" || next != 3 || truncated {
		t.Fatalf("Slice = %q, %d, %t, %v", got, next, truncated, err)
	}
	_, _ = buffer.Write([]byte("defgh")) // stream is now "abcdefgh"; window keeps "defgh"
	got, next, truncated, err = buffer.Slice(next)
	if err != nil || got != "defgh" || next != 8 || !truncated {
		t.Fatalf("Slice after rollover = %q, %d, %t, %v", got, next, truncated, err)
	}
	if buffer.Dropped() != 3 {
		t.Fatalf("Dropped = %d", buffer.Dropped())
	}
	// A cursor older than the window resumes at the start of the window.
	got, _, _, err = buffer.Slice(0)
	if err != nil || got != "defgh" {
		t.Fatalf("stale cursor Slice = %q, %v", got, err)
	}
	if _, _, _, err := buffer.Slice(9); err == nil {
		t.Fatal("cursor beyond the stream accepted")
	}
}
