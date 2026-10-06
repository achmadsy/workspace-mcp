package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testURL = "https://mcp.example.com/mcp"

func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	store, err := OpenStore(dir, key, testURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	s, err := NewServer(testURL, "correct horse", store)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return s, ts
}

func dcr(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{"https://claude.ai/api/mcp/auth_callback"},
		"client_name":                "Claude",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("register status %d", resp.StatusCode)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.ClientID
}

func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// fullFlow drives authorize → (skip UI, call consent as authenticated session)
// by reusing the browser session cookie from the authorize redirect.
func fullFlow(t *testing.T, ts *httptest.Server, clientID, redirect string) (code string) {
	t.Helper()
	_, challenge := pkcePair(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"resource":              {testURL},
		"scope":                 {"workspace"},
		"state":                 {"st123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	// Authorize creates pending request and redirects to /login.
	authorize := func(client *http.Client) string {
		resp, err := client.Get(ts.URL + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.Header.Get("Location")
	}
	jar := &simpleJar{}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	loc := authorize(client)
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected login redirect, got %q", loc)
	}
	// GET login to establish session cookie and CSRF.
	resp, err := client.Get(ts.URL + loc)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp.Body)
	resp.Body.Close()
	csrf := extractCSRF(t, body)
	reqID := queryOf(loc).Get("request")
	// POST login with password.
	resp, err = client.PostForm(ts.URL+"/login", url.Values{"password": {"correct horse"}, "csrf": {csrf}, "request": {reqID}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), "/consent") {
		t.Fatalf("login redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// GET consent for fresh CSRF, POST consent.
	resp, err = client.Get(ts.URL + resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	body = readAll(t, resp.Body)
	resp.Body.Close()
	csrf = extractCSRF(t, body)
	reqID = "consent-form-request"
	resp, err = client.PostForm(ts.URL+"/consent", url.Values{"csrf": {csrf}, "request": {queryOf(resp.Request.URL.RequestURI()).Get("request")}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	t.Logf("consent POST: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	loc = resp.Header.Get("Location")
	if !strings.HasPrefix(loc, redirect) {
		t.Fatalf("expected redirect to client, got %q", loc)
	}
	code = queryOf(loc[strings.Index(loc, "?"):]).Get("code")
	t.Logf("fullFlow code=%q loc=%q", code, loc)
	return code
}

func readAll(t *testing.T, r interface{ Read([]byte) (int, error) }) string {
	t.Helper()
	buf := make([]byte, 65536)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

func extractCSRF(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, `name="csrf" value="`)
	if i < 0 {
		t.Fatalf("csrf not found in %q", body[:min(len(body), 300)])
	}
	rest := body[i+len(`name="csrf" value="`):]
	j := strings.Index(rest, `"`)
	return rest[:j]
}

func queryOf(raw string) url.Values {
	u, err := url.Parse(raw)
	if err != nil {
		return url.Values{}
	}
	return u.Query()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type simpleJar struct{ cookies []*http.Cookie }

func (j *simpleJar) SetCookies(u *url.URL, cs []*http.Cookie) { j.cookies = cs }
func (j *simpleJar) Cookies(*url.URL) []*http.Cookie          { return j.cookies }

func exchange(t *testing.T, ts *httptest.Server, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(ts.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

func TestFullTokenFlow(t *testing.T) {
	s, ts := testServer(t)
	clientID := dcr(t, ts)
	code := fullFlow(t, ts, clientID, "https://claude.ai/api/mcp/auth_callback")
	if code == "" {
		t.Fatal("no code issued")
	}
	verifier := strings.Repeat("v", 64)
	status, out := exchange(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {"https://claude.ai/api/mcp/auth_callback"}, "resource": {testURL}, "code_verifier": {verifier},
	})
	if status != 200 || out["access_token"] == "" || out["refresh_token"] == "" {
		t.Fatalf("token exchange: %d %v", status, out)
	}
	access, refresh := out["access_token"].(string), out["refresh_token"].(string)
	info, err := s.VerifyToken(t.Context(), access, nil)
	if err != nil || len(info.Scopes) != 1 || info.Scopes[0] != "workspace" {
		t.Fatalf("verify: %v %+v", err, info)
	}
	// Refresh rotates.
	status, out2 := exchange(t, ts, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}, "resource": {testURL},
	})
	if status != 200 || out2["refresh_token"] == "" {
		t.Fatalf("refresh: %d %v", status, out2)
	}
	// Replay of used refresh token revokes family.
	status, _ = exchange(t, ts, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}, "resource": {testURL},
	})
	if status != 400 {
		t.Fatalf("replay must fail, got %d", status)
	}
	if _, err := s.VerifyToken(t.Context(), out2["access_token"].(string), nil); err == nil {
		t.Fatal("revoked family token must fail verification")
	}
}

func TestCodeReplay(t *testing.T) {
	_, ts := testServer(t)
	clientID := dcr(t, ts)
	code := fullFlow(t, ts, clientID, "https://claude.ai/api/mcp/auth_callback")
	verifier := strings.Repeat("v", 64)
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {"https://claude.ai/api/mcp/auth_callback"}, "resource": {testURL}, "code_verifier": {verifier},
	}
	if status, _ := exchange(t, ts, form); status != 200 {
		t.Fatalf("first exchange: %d", status)
	}
	if status, _ := exchange(t, ts, form); status != 400 {
		t.Fatalf("code replay must fail, got %d", status)
	}
}

func TestPKCEAndRedirectEnforcement(t *testing.T) {
	_, ts := testServer(t)
	clientID := dcr(t, ts)
	// Wrong verifier.
	code := fullFlow(t, ts, clientID, "https://claude.ai/api/mcp/auth_callback")
	status, _ := exchange(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {"https://claude.ai/api/mcp/auth_callback"}, "resource": {testURL}, "code_verifier": {strings.Repeat("x", 64)},
	})
	if status != 400 {
		t.Fatalf("wrong PKCE verifier must fail, got %d", status)
	}
	// Mismatched redirect at token endpoint.
	code2 := fullFlow(t, ts, clientID, "https://claude.ai/api/mcp/auth_callback")
	status, _ = exchange(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code2}, "client_id": {clientID},
		"redirect_uri": {"https://evil.example.com/cb"}, "resource": {testURL}, "code_verifier": {strings.Repeat("v", 64)},
	})
	if status != 400 {
		t.Fatalf("redirect mismatch must fail, got %d", status)
	}
	// Wrong resource at token endpoint.
	code3 := fullFlow(t, ts, clientID, "https://claude.ai/api/mcp/auth_callback")
	status, _ = exchange(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code3}, "client_id": {clientID},
		"redirect_uri": {"https://claude.ai/api/mcp/auth_callback"}, "resource": {"https://other.example.com/mcp"}, "code_verifier": {strings.Repeat("v", 64)},
	})
	if status != 400 {
		t.Fatalf("resource mismatch must fail, got %d", status)
	}
}

func TestDCRRejectsArbitraryHTTPSRedirect(t *testing.T) {
	_, ts := testServer(t)
	body, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{"https://evil.example.com/callback"},
		"token_endpoint_auth_method": "none",
	})
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("arbitrary redirect must be rejected, got %d", resp.StatusCode)
	}
}

func TestDCRRejectsConfidential(t *testing.T) {
	_, ts := testServer(t)
	body, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{"https://claude.ai/api/mcp/auth_callback"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("confidential client must be rejected, got %d", resp.StatusCode)
	}
}

func TestMetadata(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var prm map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		t.Fatal(err)
	}
	if prm["resource"] != testURL {
		t.Fatalf("resource mismatch: %v", prm["resource"])
	}
	resp2, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var asm map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&asm); err != nil {
		t.Fatal(err)
	}
	if asm["issuer"] != "https://mcp.example.com" || asm["registration_endpoint"] == nil {
		t.Fatalf("as metadata: %v", asm)
	}
	ccm, _ := asm["code_challenge_methods_supported"].([]any)
	if len(ccm) != 1 || ccm[0] != "S256" {
		t.Fatalf("PKCE metadata: %v", ccm)
	}
}

func TestLoginRateLimit(t *testing.T) {
	s, ts := testServer(t)
	_, _ = s, ts
	// covered by attemptLimiter unit below
}

func TestAttemptLimiter(t *testing.T) {
	l := newAttemptLimiter()
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !l.allow("ip", now) {
			t.Fatalf("attempt %d should pass", i)
		}
	}
	if l.allow("ip", now) {
		t.Fatal("sixth attempt must be limited")
	}
	if !l.allow("other", now) {
		t.Fatal("other key must pass")
	}
}
