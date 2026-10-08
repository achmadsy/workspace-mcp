package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/link/workspace-mcp/internal/config"
)

func TestBuildCapabilitiesExecEnabled(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		EnableExec: true, ExecMaxOutput: 65536, ExecMaxJobs: 4,
		ExecTimeout: 15 * time.Second, ExecJobTimeout: 10 * time.Minute, ExecJobTTL: 30 * time.Minute,
		ExecMemoryBytes: 2 << 30, ExecMaxProcesses: 512, ExecMaxFileBytes: 1 << 30, ExecCPUSeconds: 300,
	}
	got := buildCapabilities(cfg)
	if !got.Exec || !got.ExecNetwork || got.GitNetwork || got.GitCredentialMode != "" {
		t.Fatalf("gates = %#v", got)
	}
	l := got.Limits
	if l.ExecTimeoutMS != 15000 || l.ExecJobTimeoutMS != 600000 || l.ExecJobTTLSecs != 1800 ||
		l.ExecMemoryBytes != 2<<30 || l.ExecMaxProcesses != 512 || l.ExecMaxFileBytes != 1<<30 ||
		l.ExecCPUSeconds != 300 || l.MaxExecOutput != 65536 || l.MaxExecJobs != 4 {
		t.Fatalf("limits = %#v", l)
	}
}

func TestBuildCapabilitiesExecDisabledOmitsExecLimits(t *testing.T) {
	t.Parallel()

	// Exec limits are configured but exec is off: they must not be advertised.
	cfg := config.Config{ExecTimeout: 15 * time.Second, ExecMemoryBytes: 1 << 30}
	got := buildCapabilities(cfg)
	if got.Exec || got.ExecNetwork || got.Limits.ExecTimeoutMS != 0 || got.Limits.ExecMemoryBytes != 0 {
		t.Fatalf("exec disabled but advertised: %#v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "exec_timeout_ms") || strings.Contains(string(raw), "git_credential_mode") {
		t.Fatalf("omitted fields present in %s", raw)
	}
}

func TestBuildCapabilitiesCredentialModeWithoutPaths(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		EnableGitNetwork: true, GitCredentialMode: "ssh",
		GitCredentialFile: "/secret/id_ed25519", GitKnownHostsFile: "/secret/known_hosts",
	}
	got := buildCapabilities(cfg)
	if got.GitCredentialMode != "ssh" || !got.GitNetwork {
		t.Fatalf("capabilities = %#v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "/secret") || strings.Contains(string(raw), "id_ed25519") {
		t.Fatalf("credential paths leaked: %s", raw)
	}
}
