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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/link/workspace-mcp/internal/config"
	gitservice "github.com/link/workspace-mcp/internal/git"
	"github.com/link/workspace-mcp/internal/sandboxexec"
	"github.com/link/workspace-mcp/internal/workspace"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func TestToolScopeGuards(t *testing.T) {
	public := config.Config{Mode: config.ModePublic}
	local := config.Config{Mode: config.ModeLocal}
	if err := requireScope(local, nil, "workspace:exec"); err != nil {
		t.Fatalf("local scope guard: %v", err)
	}
	if err := requireScope(public, nil, "workspace:exec"); err == nil {
		t.Fatal("public request without token accepted")
	}
	req := &mcp.CallToolRequest{Extra: &mcp.RequestExtra{TokenInfo: &mcpauth.TokenInfo{
		Scopes: []string{"workspace", "workspace:exec"}, Extra: map[string]any{"client_id": "client-a"},
	}}}
	if err := requireScope(public, req, "workspace:exec"); err != nil {
		t.Fatalf("granted scope rejected: %v", err)
	}
	if err := requireScope(public, req, "workspace:git-write"); err == nil {
		t.Fatal("missing scope accepted")
	}
	if owner := toolOwner(public, req); owner != "client-a" {
		t.Fatalf("owner = %q", owner)
	}
}

func TestBaseToolsAndCalls(t *testing.T) {
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
	want := []string{
		"server_capabilities", "workspace_list", "workspace_read", "workspace_stat", "workspace_read_range", "workspace_glob",
		"workspace_search", "workspace_write", "workspace_edit", "workspace_mkdir", "workspace_delete", "workspace_move",
		"workspace_copy", "workspace_apply_patch", "git_status", "git_diff", "git_log", "git_show", "git_branches", "git_remotes",
	}
	if len(names) != len(want) {
		t.Fatalf("tool count %d, want %d: %v", len(names), len(want), names)
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

	// Exercise remaining base tools via RPC.
	capCall := call("9", "server_capabilities", map[string]any{})
	if capCall["error"] != nil {
		t.Fatalf("server_capabilities error: %v", capCall["error"])
	}

	statCall := call("10", "workspace_stat", map[string]any{"path": "main.go"})
	if statCall["error"] != nil {
		t.Fatalf("workspace_stat error: %v", statCall["error"])
	}

	rangeCall := call("11", "workspace_read_range", map[string]any{"path": "main.go", "offset": 0, "length": 7})
	if rangeCall["error"] != nil {
		t.Fatalf("workspace_read_range error: %v", rangeCall["error"])
	}

	globCall := call("12", "workspace_glob", map[string]any{"pattern": "*.go"})
	if globCall["error"] != nil {
		t.Fatalf("workspace_glob error: %v", globCall["error"])
	}

	mkdirCall := call("13", "workspace_mkdir", map[string]any{"path": "sub/nested", "parents": true})
	if mkdirCall["error"] != nil {
		t.Fatalf("workspace_mkdir error: %v", mkdirCall["error"])
	}

	copyCall := call("14", "workspace_copy", map[string]any{"source": "main.go", "destination": "sub/copy.go"})
	if copyCall["error"] != nil {
		t.Fatalf("workspace_copy error: %v", copyCall["error"])
	}

	moveCall := call("15", "workspace_move", map[string]any{"source": "sub/copy.go", "destination": "sub/moved.go"})
	if moveCall["error"] != nil {
		t.Fatalf("workspace_move error: %v", moveCall["error"])
	}

	delCall := call("16", "workspace_delete", map[string]any{"path": "sub/moved.go", "recursive": false})
	if delCall["error"] != nil {
		t.Fatalf("workspace_delete error: %v", delCall["error"])
	}

	patchCall := call("17", "workspace_apply_patch", map[string]any{
		"patch": "--- a/main.go\n+++ b/main.go\n@@ -1,3 +1,3 @@\n package main\n \n-func Greet() {}\n+func Hello() {}\n",
	})
	if patchCall["error"] != nil {
		t.Fatalf("workspace_apply_patch error: %v", patchCall["error"])
	}

	gitCalls := []struct {
		name string
		args map[string]any
	}{
		{"git_status", map[string]any{}},
		{"git_diff", map[string]any{}},
		{"git_branches", map[string]any{}},
		{"git_remotes", map[string]any{}},
		{"git_log", map[string]any{"max_count": 5}},
		{"git_show", map[string]any{"revision": "HEAD"}},
	}
	for i, gc := range gitCalls {
		res := call(strconv.Itoa(20+i), gc.name, gc.args)
		if res["error"] != nil {
			t.Fatalf("%s error: %v", gc.name, res["error"])
		}
	}
}

func TestCommandDigest(t *testing.T) {
	reqScript := sandboxexec.Request{Script: "echo hello"}
	reqArgv := sandboxexec.Request{Argv: []string{"echo", "hello"}}
	d1 := commandDigest(reqScript)
	d2 := commandDigest(reqArgv)
	if d1 == "" || d2 == "" {
		t.Fatal("empty command digest")
	}
	if d1 == d2 {
		t.Fatal("script and argv produced identical digest")
	}
	// Deterministic.
	if commandDigest(reqScript) != d1 {
		t.Fatal("digest is not deterministic")
	}
}

func TestToolOwnerEdgeCases(t *testing.T) {
	local := config.Config{Mode: config.ModeLocal}
	public := config.Config{Mode: config.ModePublic}
	if owner := toolOwner(local, nil); owner != "local" {
		t.Fatalf("local owner: %s", owner)
	}
	if owner := toolOwner(public, nil); owner != "unauthorized" {
		t.Fatalf("public nil req owner: %s", owner)
	}
	if owner := toolOwner(public, &mcp.CallToolRequest{}); owner != "unauthorized" {
		t.Fatalf("public no extra owner: %s", owner)
	}
	if owner := toolOwner(public, &mcp.CallToolRequest{Extra: &mcp.RequestExtra{}}); owner != "unauthorized" {
		t.Fatalf("public no token owner: %s", owner)
	}
	reqEmptyClient := &mcp.CallToolRequest{Extra: &mcp.RequestExtra{TokenInfo: &mcpauth.TokenInfo{
		Extra: map[string]any{"client_id": ""},
	}}}
	if owner := toolOwner(public, reqEmptyClient); owner != "unauthorized" {
		t.Fatalf("public empty client owner: %s", owner)
	}
}

func TestAgenticToolRegistrationAndGuards(t *testing.T) {
	dir := t.TempDir()
	r, err := workspace.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	gs := gitservice.New("", r)

	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1.0"}, nil)
	cfg := config.Config{
		Mode:             config.ModePublic,
		EnableGitWrite:   true,
		EnableGitNetwork: true,
		EnableExec:       true,
		ExecTimeout:      10 * time.Second,
	}

	registerGitWriteTools(mcpSrv, cfg, gs, false)
	registerGitNetworkTools(mcpSrv, cfg, gs, true)
	registerExecTools(mcpSrv, cfg, nil, nil, true)

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpSrv }, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	call := func(id, name string, args map[string]any) map[string]any {
		return rpc(t, ts.URL, id, "tools/call", map[string]any{"name": name, "arguments": args})
	}
	for _, toolName := range []string{
		"git_add", "git_restore", "git_commit", "git_branch", "git_switch",
		"git_stash_push", "git_stash_pop", "git_fetch", "git_pull", "git_push",
		"exec_run", "exec_start", "exec_status", "exec_cancel",
	} {
		out := call("1", toolName, map[string]any{})
		res, ok := out["result"].(map[string]any)
		if !ok || res["isError"] != true {
			t.Fatalf("%s without scope must return tool error: %v", toolName, out)
		}
	}
}

func TestLocalAgenticToolsCallAndAudit(t *testing.T) {
	dir := t.TempDir()
	r, err := workspace.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	gs := gitservice.New("", r)

	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1.0"}, nil)
	cfg := config.Config{
		Mode:             config.ModeLocal,
		EnableGitWrite:   true,
		EnableGitNetwork: true,
	}

	registerGitWriteTools(mcpSrv, cfg, gs, false)
	registerGitNetworkTools(mcpSrv, cfg, gs, true)

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpSrv }, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	call := func(id, name string, args map[string]any) map[string]any {
		return rpc(t, ts.URL, id, "tools/call", map[string]any{"name": name, "arguments": args})
	}

	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"git_add", map[string]any{"paths": []string{"file.txt"}}},
		{"git_restore", map[string]any{"paths": []string{"file.txt"}, "staged": true}},
		{"git_commit", map[string]any{"message": "commit msg"}},
		{"git_branch", map[string]any{"name": "test-branch"}},
		{"git_switch", map[string]any{"branch": "main"}},
		{"git_stash_push", map[string]any{"message": "stash msg"}},
		{"git_stash_pop", map[string]any{"index": 0}},
		{"git_fetch", map[string]any{"remote": "origin"}},
		{"git_pull", map[string]any{"remote": "origin", "branch": "main"}},
		{"git_push", map[string]any{"remote": "origin", "refspec": "main"}},
	} {
		out := call("1", tc.name, tc.args)
		res, ok := out["result"].(map[string]any)
		if !ok || res["isError"] != true {
			t.Fatalf("%s without runner must fail safely: %v", tc.name, out)
		}
	}

	// Verify auditTool with X-Request-ID header.
	reqWithHeader := &mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: http.Header{"X-Request-ID": []string{"req-12345"}}}}
	auditTool(reqWithHeader, "test_tool", "key", "val")
	auditGit(reqWithHeader, "test_git", gitservice.Result{}, nil, "key", "val")
}
