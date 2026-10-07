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
