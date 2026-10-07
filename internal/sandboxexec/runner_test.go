//go:build linux

package sandboxexec

import (
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
	if len(files) != 2 {
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
	if len(files) != 2 || len(generated) != 1 {
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
	}
}
