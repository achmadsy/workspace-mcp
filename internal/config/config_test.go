package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		if v == "" {
			os.Unsetenv(k)
		} else {
			t.Setenv(k, v)
		}
	}
}

var key64 = base64.StdEncoding.EncodeToString(make([]byte, 32))

func baseEnvs(dir string) map[string]string {
	return map[string]string{
		"WORKSPACE_ROOT":     dir,
		"MCP_MODE":           "local",
		"MCP_PUBLIC_URL":     "",
		"MCP_ADMIN_PASSWORD": "",
		"MCP_STATE_DIR":      "",
		"MCP_STATE_KEY":      "",
	}
}

func TestLocalMode(t *testing.T) {
	dir := t.TempDir()
	setEnv(t, baseEnvs(dir))
	c, err := Load()
	if err != nil {
		t.Fatalf("local mode: %v", err)
	}
	if c.Address() != "127.0.0.1:8787" {
		t.Fatalf("address: %q", c.Address())
	}
}

func TestAgenticTimeoutOrdering(t *testing.T) {
	dir := t.TempDir()
	env := baseEnvs(dir)
	env["MCP_EXEC_TIMEOUT"] = "20s"
	env["MCP_EXEC_JOB_TIMEOUT"] = "10s"
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("job timeout shorter than synchronous timeout must be rejected")
	}
}

func TestLocalModeRejectsNonLoopback(t *testing.T) {
	dir := t.TempDir()
	env := baseEnvs(dir)
	env["MCP_HOST"] = "0.0.0.0"
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("0.0.0.0 must be rejected without explicit override")
	}
}

func TestPublicModeRequires(t *testing.T) {
	dir := t.TempDir()
	env := baseEnvs(dir)
	env["MCP_MODE"] = "public"
	env["MCP_ADMIN_PASSWORD"] = "test-password-1234"
	env["MCP_STATE_DIR"] = filepath.Join(dir, "state")
	env["MCP_STATE_KEY"] = key64
	env["MCP_PUBLIC_URL"] = "http://mcp.example.com/mcp" // http must fail
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("http public URL must be rejected")
	}
	env["MCP_PUBLIC_URL"] = "https://mcp.example.com/" // wrong path must fail
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("non-/mcp path must be rejected")
	}
	env["MCP_PUBLIC_URL"] = "https://mcp.example.com/mcp"
	setEnv(t, env)
	c, err := Load()
	if err != nil {
		t.Fatalf("valid public config: %v", err)
	}
	if c.Origin() != "https://mcp.example.com" {
		t.Fatalf("origin: %q", c.Origin())
	}
	// Default client origins for remote MCP connectors.
	if len(c.AllowedOrigins) != 2 || c.AllowedOrigins[0] != "https://claude.ai" || c.AllowedOrigins[1] != "https://claude.com" {
		t.Fatalf("default allowed origins: %q", c.AllowedOrigins)
	}
	// Explicit override replaces defaults; trailing slashes trimmed.
	setEnv(t, map[string]string{"MCP_ALLOWED_ORIGINS": "https://claude.ai/, https://other.example.com ,"})
	c, err = Load()
	if err != nil {
		t.Fatalf("override allowed origins: %v", err)
	}
	if len(c.AllowedOrigins) != 2 || c.AllowedOrigins[0] != "https://claude.ai" || c.AllowedOrigins[1] != "https://other.example.com" {
		t.Fatalf("override allowed origins: %q", c.AllowedOrigins)
	}
	// Empty override falls back to defaults.
	setEnv(t, map[string]string{"MCP_ALLOWED_ORIGINS": ""})
	c, err = Load()
	if err != nil {
		t.Fatalf("empty allowed origins: %v", err)
	}
	if len(c.AllowedOrigins) != 2 {
		t.Fatalf("empty override must use defaults: %q", c.AllowedOrigins)
	}
	env["MCP_STATE_KEY"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("short key must be rejected")
	}
}

func TestConfigValidationEdgeCases(t *testing.T) {
	dir := t.TempDir()

	// Git network requires Git write.
	env := baseEnvs(dir)
	env["MCP_ENABLE_GIT_NETWORK"] = "true"
	env["MCP_ENABLE_GIT_WRITE"] = "false"
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("MCP_ENABLE_GIT_NETWORK without MCP_ENABLE_GIT_WRITE must be rejected")
	}

	// Invalid port.
	for _, badPort := range []string{"0", "70000", "not-a-port"} {
		env = baseEnvs(dir)
		env["MCP_PORT"] = badPort
		setEnv(t, env)
		if _, err := Load(); err == nil {
			t.Fatalf("invalid port %q accepted", badPort)
		}
	}

	// Invalid WorkspaceRoot.
	for _, badRoot := range []string{"", "relative/path", filepath.Join(dir, "nonexistent")} {
		env = baseEnvs(dir)
		env["WORKSPACE_ROOT"] = badRoot
		setEnv(t, env)
		if _, err := Load(); err == nil {
			t.Fatalf("invalid workspace root %q accepted", badRoot)
		}
	}

	// File instead of directory for WorkspaceRoot.
	filePath := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	env = baseEnvs(dir)
	env["WORKSPACE_ROOT"] = filePath
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("workspace root as file accepted")
	}

	// Invalid Host.
	env = baseEnvs(dir)
	env["MCP_HOST"] = "not-an-ip"
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("invalid host accepted")
	}

	// Invalid Mode.
	env = baseEnvs(dir)
	env["MCP_MODE"] = "unsupported"
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("invalid mode accepted")
	}

	// Resource limit validation bounds.
	for k, v := range map[string]string{
		"MCP_EXEC_MAX_OUTPUT": "100", // < 4096
		"MCP_EXEC_MAX_JOBS":   "0",   // < 1
		"MCP_EXEC_TIMEOUT":    "0s",  // <= 0
	} {
		env = baseEnvs(dir)
		env[k] = v
		setEnv(t, env)
		if _, err := Load(); err == nil {
			t.Fatalf("invalid resource %s=%s accepted", k, v)
		}
	}
}

func TestAgenticResourceDefaultsAndBounds(t *testing.T) {
	dir := t.TempDir()
	setEnv(t, baseEnvs(dir))
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// File size is an independent limit, not derived from the output limit.
	if c.ExecMaxFileBytes != 1<<30 || c.ExecMemoryBytes != 2<<30 || c.ExecMaxProcesses != 512 {
		t.Fatalf("unexpected defaults: file=%d memory=%d procs=%d", c.ExecMaxFileBytes, c.ExecMemoryBytes, c.ExecMaxProcesses)
	}
	for k, v := range map[string]string{
		"MCP_EXEC_MAX_FILE_BYTES": "1024",   // below 1 MiB
		"MCP_EXEC_MEMORY_BYTES":   "banana", // unparsable input must not wrap to a huge limit
		"MCP_EXEC_MAX_PROCESSES":  "-5",
	} {
		env := baseEnvs(dir)
		env[k] = v
		setEnv(t, env)
		if _, err := Load(); err == nil {
			t.Fatalf("invalid %s=%s accepted", k, v)
		}
		os.Unsetenv(k)
	}
}

func TestEnvBoolDefault(t *testing.T) {
	t.Setenv("MCP_TEST_BOOL", "")
	if !envBoolDefault("MCP_TEST_BOOL", true) || envBoolDefault("MCP_TEST_BOOL", false) {
		t.Fatal("unset variable must return the default")
	}
	t.Setenv("MCP_TEST_BOOL", "false")
	if envBoolDefault("MCP_TEST_BOOL", true) {
		t.Fatal("explicit false ignored")
	}
	t.Setenv("MCP_TEST_BOOL", "not-a-bool")
	if !envBoolDefault("MCP_TEST_BOOL", true) {
		t.Fatal("invalid value must fall back to the default")
	}
}

func TestSecureCredentialFile(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()

	// Empty and relative path.
	if err := secureCredentialFile("", ws); err == nil {
		t.Fatal("empty path accepted")
	}
	if err := secureCredentialFile("relative/path", ws); err == nil {
		t.Fatal("relative path accepted")
	}

	// Inside workspace.
	insideFile := filepath.Join(ws, "cred")
	if err := os.WriteFile(insideFile, []byte("sec"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureCredentialFile(insideFile, ws); err == nil {
		t.Fatal("inside workspace credential accepted")
	}

	// Nonexistent file.
	if err := secureCredentialFile(filepath.Join(outside, "missing"), ws); err == nil {
		t.Fatal("missing file accepted")
	}

	// Directory instead of regular file.
	credDir := filepath.Join(outside, "dir")
	if err := os.Mkdir(credDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureCredentialFile(credDir, ws); err == nil {
		t.Fatal("directory accepted as credential file")
	}

	// World/group readable file.
	worldFile := filepath.Join(outside, "world")
	if err := os.WriteFile(worldFile, []byte("sec"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := secureCredentialFile(worldFile, ws); err == nil {
		t.Fatal("world-readable credential accepted")
	}

	// Valid regular file.
	validFile := filepath.Join(outside, "valid")
	if err := os.WriteFile(validFile, []byte("sec"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureCredentialFile(validFile, ws); err != nil {
		t.Fatalf("valid credential file rejected: %v", err)
	}
}
