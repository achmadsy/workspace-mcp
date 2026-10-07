package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/link/workspace-mcp/internal/config"
)

func startTestServer(t *testing.T) (base string, root string) {
	t.Helper()
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		_ = out
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc Greet() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		WorkspaceRoot: dir,
		Host:          "127.0.0.1",
		Port:          0,
		Mode:          config.ModeLocal,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	ts := httptest.NewServer(s.handler())
	t.Cleanup(ts.Close)
	return ts.URL, dir
}

func rpc(t *testing.T, base, id, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	req, _ := http.NewRequest("POST", base+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("%s: decode: %v", method, err)
	}
	return out
}

func TestPublicOriginPolicy(t *testing.T) {
	dir := t.TempDir()
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	cfg := config.Config{
		WorkspaceRoot:  dir,
		Host:           "127.0.0.1",
		Port:           8787,
		Mode:           config.ModePublic,
		PublicURL:      "https://mcp.example.com/mcp",
		AdminPassword:  "correct horse battery staple",
		StateDir:       filepath.Join(t.TempDir(), "state"),
		StateKey:       key,
		AllowedOrigins: []string{"https://claude.ai", "https://claude.com"},
		TrustTunnel:    true,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	ts := httptest.NewServer(s.handler())
	t.Cleanup(ts.Close)

	request := func(path, origin, body, contentType string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", origin)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	login := request("/login", "https://claude.ai", "", "application/x-www-form-urlencoded")
	loginBody, _ := io.ReadAll(login.Body)
	login.Body.Close()
	if login.StatusCode == http.StatusForbidden && strings.Contains(string(loginBody), "forbidden origin") {
		t.Fatal("OAuth login must reach its CSRF handler")
	}

	// Claude.ai is a default-allowed client origin: it must pass the Origin
	// gate and reach bearer-token auth (401 without a token), not 403.
	mcp := request("/mcp", "https://claude.ai", `{}`, "application/json")
	mcpBody, _ := io.ReadAll(mcp.Body)
	mcp.Body.Close()
	if mcp.StatusCode != http.StatusUnauthorized || strings.Contains(string(mcpBody), "forbidden origin") {
		t.Fatalf("allowed client origin must reach bearer auth: %d %q", mcp.StatusCode, mcpBody)
	}

	evil := request("/mcp", "https://evil.example.com", `{}`, "application/json")
	evilBody, _ := io.ReadAll(evil.Body)
	evil.Body.Close()
	if evil.StatusCode != http.StatusForbidden || !strings.Contains(string(evilBody), "forbidden origin") {
		t.Fatalf("foreign MCP origin must be rejected: %d %q", evil.StatusCode, evilBody)
	}

	// Cloudflare connects from loopback and preserves the public Host header.
	// Trusted-tunnel mode must let that shape reach bearer auth rather than the
	// SDK's localhost Host-header rejection.
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "mcp.example.com"
	req.Header.Set("Origin", "https://claude.ai")
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8787}))
	proxyShape := httptest.NewRecorder()
	s.handler().ServeHTTP(proxyShape, req)
	if proxyShape.Code != http.StatusUnauthorized || strings.Contains(proxyShape.Body.String(), "invalid Host header") {
		t.Fatalf("trusted tunnel must bypass SDK localhost protection: %d %q", proxyShape.Code, proxyShape.Body.String())
	}
}

func TestSevenToolsAndCalls(t *testing.T) {
	base, _ := startTestServer(t)
	out := rpc(t, base, "1", "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "0"},
	})
	res := out["result"].(map[string]any)
	if res["serverInfo"].(map[string]any)["name"] != "workspace-mcp" {
		t.Fatalf("initialize: %v", res)
	}
	list := rpc(t, base, "2", "tools/list", map[string]any{})
	tools := list["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	want := []string{"workspace_list", "workspace_read", "workspace_search", "workspace_write", "workspace_edit", "git_status", "git_diff"}
	if len(names) != len(want) {
		t.Fatalf("tool count %d, want 7: %v", len(names), names)
	}
	for _, w := range want {
		if !names[w] {
			t.Fatalf("missing tool %s", w)
		}
	}
	call := func(id, name string, args map[string]any) map[string]any {
		return rpc(t, base, id, "tools/call", map[string]any{"name": name, "arguments": args})
	}
	for id, c := range map[string]struct {
		name string
		args map[string]any
	}{
		"3": {"workspace_list", map[string]any{"path": "", "depth": 2}},
		"4": {"workspace_read", map[string]any{"path": "main.go"}},
		"5": {"workspace_search", map[string]any{"query": "Greet"}},
		"6": {"workspace_write", map[string]any{"path": "n/x.md", "content": "hi\n"}},
		"7": {"workspace_edit", map[string]any{"path": "n/x.md", "old_text": "hi", "new_text": "hello"}},
	} {
		if out := call(id, c.name, c.args); out["error"] != nil {
			t.Fatalf("%s error: %v", c.name, out["error"])
		}
	}
	out = call("8", "workspace_read", map[string]any{"path": "../../etc/passwd"})
	res = out["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("traversal must be tool error: %v", out)
	}
}
