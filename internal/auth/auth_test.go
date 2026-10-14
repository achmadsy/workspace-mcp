package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

func registerClient(t *testing.T, ts *httptest.Server, in map[string]any) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(in)
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(string(body)))
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

func dcrWithRedirect(t *testing.T, ts *httptest.Server, redirect string) string {
	t.Helper()
	status, out := registerClient(t, ts, map[string]any{
		"redirect_uris":              []string{redirect},
		"client_name":                "Claude",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	if status != http.StatusCreated {
		t.Fatalf("register status %d: %v", status, out)
	}
	clientID, _ := out["client_id"].(string)
	if clientID == "" {
		t.Fatalf("register response missing client_id: %v", out)
	}
	return clientID
}

func dcr(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	return dcrWithRedirect(t, ts, "https://claude.ai/api/mcp/auth_callback")
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
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/consent") {
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
	body = readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" {
		t.Fatalf("consent POST status %d Location %q, want 200 without redirect", resp.StatusCode, resp.Header.Get("Location"))
	}
	loc = extractCompletionLocation(t, body)
	t.Logf("consent completion: %d %q", resp.StatusCode, loc)
	gotRedirect, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	wantRedirect, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse expected redirect: %v", err)
	}
	if gotRedirect.Scheme != wantRedirect.Scheme || gotRedirect.Host != wantRedirect.Host || gotRedirect.Path != wantRedirect.Path {
		t.Fatalf("expected redirect to %q, got %q", redirect, loc)
	}
	for key, values := range wantRedirect.Query() {
		if !sameStrings(gotRedirect.Query()[key], values) {
			t.Fatalf("redirect query %q changed: want %v, got %v", key, values, gotRedirect.Query()[key])
		}
	}
	code = gotRedirect.Query().Get("code")
	t.Logf("fullFlow code=%q loc=%q", code, loc)
	return code
}

func readAll(t *testing.T, r interface{ Read([]byte) (int, error) }) string {
	t.Helper()
	buf := make([]byte, 65536)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

func extractCompletionLocation(t *testing.T, body string) string {
	t.Helper()
	extract := func(marker string) string {
		i := strings.Index(body, marker)
		if i < 0 {
			t.Fatalf("completion target %q not found in %q", marker, body[:min(len(body), 500)])
		}
		rest := body[i+len(marker):]
		j := strings.Index(rest, `"`)
		if j < 0 {
			t.Fatalf("completion target %q is malformed in %q", marker, body[:min(len(body), 500)])
		}
		return html.UnescapeString(rest[:j])
	}
	refresh := extract(`<meta http-equiv="refresh" content="0;url=`)
	link := extract(`<a href="`)
	if refresh != link {
		t.Fatalf("completion targets differ: meta refresh %q, link %q", refresh, link)
	}
	return link
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

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

func TestDCRCompatibility(t *testing.T) {
	_, ts := testServer(t)
	tests := []struct {
		name     string
		input    map[string]any
		wantCode int
	}{
		{
			name: "RFC metadata and authorization code subset",
			input: map[string]any{
				"redirect_uris":              []string{"https://connect.example.com:8443/oauth/callback?source=claude"},
				"client_name":                "Claude",
				"client_uri":                 "https://claude.ai",
				"logo_uri":                   "https://claude.ai/logo.png",
				"scope":                      "workspace",
				"contacts":                   []string{"mcp@example.com"},
				"grant_types":                []string{"authorization_code"},
				"response_types":             []string{"code"},
				"token_endpoint_auth_method": "none",
			},
			wantCode: http.StatusCreated,
		},
		{
			name: "omitted optional metadata",
			input: map[string]any{
				"redirect_uris": []string{"https://connect.example.com/callback"},
			},
			wantCode: http.StatusCreated,
		},
		{
			name: "loopback callback",
			input: map[string]any{
				"redirect_uris": []string{"http://127.0.0.1:49152/callback"},
			},
			wantCode: http.StatusCreated,
		},
		{
			name: "HTTPS fragment",
			input: map[string]any{
				"redirect_uris": []string{"https://connect.example.com/callback#fragment"},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "HTTPS userinfo",
			input: map[string]any{
				"redirect_uris": []string{"https://user:pass@connect.example.com/callback"},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "non-loopback HTTP",
			input: map[string]any{
				"redirect_uris": []string{"http://connect.example.com/callback"},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "wrong loopback path",
			input: map[string]any{
				"redirect_uris": []string{"http://localhost/not-callback"},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "unsupported grant",
			input: map[string]any{
				"redirect_uris": []string{"https://connect.example.com/callback"},
				"grant_types":   []string{"client_credentials"},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "refresh only",
			input: map[string]any{
				"redirect_uris": []string{"https://connect.example.com/callback"},
				"grant_types":   []string{"refresh_token"},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "unsupported response type",
			input: map[string]any{
				"redirect_uris":  []string{"https://connect.example.com/callback"},
				"response_types": []string{"token"},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "empty redirects",
			input: map[string]any{
				"redirect_uris": []string{},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "confidential client",
			input: map[string]any{
				"redirect_uris":              []string{"https://connect.example.com/callback"},
				"token_endpoint_auth_method": "client_secret_basic",
			},
			wantCode: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, out := registerClient(t, ts, tt.input)
			if status != tt.wantCode {
				t.Fatalf("register status %d, want %d: %v", status, tt.wantCode, out)
			}
			if status == http.StatusCreated {
				if out["client_id"] == "" || out["token_endpoint_auth_method"] != "none" {
					t.Fatalf("invalid registration response: %v", out)
				}
			}
		})
	}
}

func TestDCRRejectsTooManyRedirects(t *testing.T) {
	_, ts := testServer(t)
	redirects := make([]string, 9)
	for i := range redirects {
		redirects[i] = "https://connect.example.com/callback"
	}
	status, _ := registerClient(t, ts, map[string]any{"redirect_uris": redirects})
	if status != http.StatusBadRequest {
		t.Fatalf("too many redirects must be rejected, got %d", status)
	}
}

func TestArbitraryHTTPSRedirectFlow(t *testing.T) {
	_, ts := testServer(t)
	redirect := "https://connect.example.com/oauth/callback?source=claude"
	clientID := dcrWithRedirect(t, ts, redirect)
	code := fullFlow(t, ts, clientID, redirect)
	status, out := exchange(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "resource": {testURL}, "code_verifier": {strings.Repeat("v", 64)},
	})
	if status != http.StatusOK || out["access_token"] == "" {
		t.Fatalf("token exchange: %d %v", status, out)
	}
}

func TestEnabledScopeMetadata(t *testing.T) {
	base, _ := testServer(t)
	s, err := NewServer("https://mcp.example.com/mcp", "test-password-1234", base.store, "workspace:exec", "workspace:git-write", "workspace:git-network")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
	w := httptest.NewRecorder()
	s.protectedMetadata(w, r)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	scopes := body["scopes_supported"].([]any)
	if len(scopes) != 4 {
		t.Fatalf("scopes = %#v", scopes)
	}
	if !s.validScope("workspace workspace:exec workspace:git-write workspace:git-network") {
		t.Fatal("enabled scope set rejected")
	}
	if s.validScope("workspace workspace:unknown") {
		t.Fatal("unknown scope accepted")
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

func TestConsentAllowsRegisteredCallbackInCSP(t *testing.T) {
	_, ts := testServer(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := dcrWithRedirect(t, ts, redirect)
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
	jar := &simpleJar{}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(ts.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected login redirect, got %q", loc)
	}
	resp, err = client.Get(ts.URL + loc)
	if err != nil {
		t.Fatal(err)
	}
	loginCSP := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(loginCSP, "form-action 'self' https://mcp.example.com") || strings.Contains(loginCSP, "unsafe-allow-redirects") || strings.Contains(loginCSP, "claude.ai") {
		t.Fatalf("login CSP must allow only self and the explicit server origin: %q", loginCSP)
	}
	loginBody := readAll(t, resp.Body)
	resp.Body.Close()

	resp, err = client.PostForm(ts.URL+"/login", url.Values{"password": {"correct horse"}, "csrf": {extractCSRF(t, loginBody)}, "request": {queryOf(loc).Get("request")}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/consent") {
		t.Fatalf("login redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Consent page for a second client must advertise only its own callback.
	otherRedirect := "https://connect.example.com:8443/oauth/callback"
	otherClientID := dcrWithRedirect(t, ts, otherRedirect)
	_, challenge2 := pkcePair(t)
	q2 := url.Values{
		"response_type":         {"code"},
		"client_id":             {otherClientID},
		"redirect_uri":          {otherRedirect},
		"resource":              {testURL},
		"scope":                 {"workspace"},
		"code_challenge":        {challenge2},
		"code_challenge_method": {"S256"},
	}
	resp, err = client.Get(ts.URL + "/authorize?" + q2.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Location"), "/consent") {
		t.Fatalf("expected consent redirect, got %q", resp.Header.Get("Location"))
	}

	resp, err = client.Get(ts.URL + resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	consentCSP := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(consentCSP, "form-action 'self' https://mcp.example.com") || strings.Contains(consentCSP, "connect.example.com") || strings.Contains(consentCSP, "unsafe-allow-redirects") {
		t.Fatalf("consent CSP must allow only self and the explicit server origin: %q", consentCSP)
	}
	if strings.Contains(consentCSP, "claude.ai") {
		t.Fatalf("consent CSP must not allow unrelated callbacks: %q", consentCSP)
	}
	resp.Body.Close()
}

func TestGrantedScopeExpandsBareWorkspace(t *testing.T) {
	s, err := NewServer(testURL, "pw", nil, "workspace:exec", "workspace:git-write")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, requested, want string }{
		{"bare workspace expands", "workspace", "workspace workspace:exec workspace:git-write"},
		{"explicit scopes kept", "workspace workspace:exec", "workspace workspace:exec"},
		{"extra whitespace expands", "  workspace  ", "workspace workspace:exec workspace:git-write"},
	} {
		if got := s.grantedScope(test.requested); got != test.want {
			t.Errorf("%s: grantedScope(%q) = %q, want %q", test.name, test.requested, got, test.want)
		}
	}

	// With no optional gates enabled the expansion is the base scope only.
	base, err := NewServer(testURL, "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := base.grantedScope("workspace"); got != "workspace" {
		t.Errorf("base-only server granted %q", got)
	}
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

// beginConsent drives authorize and login, returning an authenticated client
// plus fresh consent CSRF and request ID.
func beginConsent(t *testing.T, ts *httptest.Server, clientID, redirect string) (*http.Client, string, string) {
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
	jar := &simpleJar{}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(ts.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("authorize redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	loc := resp.Header.Get("Location")
	resp, err = client.Get(ts.URL + loc)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp.Body)
	resp.Body.Close()
	csrf := extractCSRF(t, body)
	reqID := queryOf(loc).Get("request")
	resp, err = client.PostForm(ts.URL+"/login", url.Values{"password": {"correct horse"}, "csrf": {csrf}, "request": {reqID}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/consent") {
		t.Fatalf("login redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	consentLoc := resp.Header.Get("Location")
	resp, err = client.Get(ts.URL + consentLoc)
	if err != nil {
		t.Fatal(err)
	}
	body = readAll(t, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("consent page: %d", resp.StatusCode)
	}
	return client, extractCSRF(t, body), queryOf(consentLoc).Get("request")
}

func postConsent(t *testing.T, client *http.Client, ts *httptest.Server, csrf, reqID string) (int, string) {
	t.Helper()
	resp, err := client.PostForm(ts.URL+"/consent", url.Values{"csrf": {csrf}, "request": {reqID}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(t, resp.Body)
	if resp.Header.Get("Location") != "" {
		t.Fatalf("consent completion must not use an HTTP redirect: %q", resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, ""
	}
	for name, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header.Get(name); got != want {
			t.Fatalf("completion %s = %q, want %q", name, got, want)
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("completion CSP is not restrictive: %q", csp)
	}
	return resp.StatusCode, extractCompletionLocation(t, body)
}

func countGrants(t *testing.T, s *Server) int {
	t.Helper()
	n := 0
	_ = s.store.view(func(st *state) error { n = len(st.Codes); return nil })
	return n
}

func TestGeminiCallbackFlow(t *testing.T) {
	s, ts := testServer(t)
	redirect := "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-test"
	clientID := dcrWithRedirect(t, ts, redirect)
	code := fullFlow(t, ts, clientID, redirect)
	if code == "" {
		t.Fatal("no code issued")
	}
	verifier := strings.Repeat("v", 64)
	status, out := exchange(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "resource": {testURL}, "code_verifier": {verifier},
	})
	if status != 200 || out["access_token"] == "" {
		t.Fatalf("gemini token exchange: %d %v", status, out)
	}
	if _, err := s.VerifyToken(t.Context(), out["access_token"].(string), nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestConsentPostRendersCompletionPage(t *testing.T) {
	_, ts := testServer(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := dcrWithRedirect(t, ts, redirect)
	client, csrf, reqID := beginConsent(t, ts, clientID, redirect)
	status, loc := postConsent(t, client, ts, csrf, reqID)
	if status != http.StatusOK {
		t.Fatalf("consent POST status %d, want 200", status)
	}
	if got, err := url.Parse(loc); err != nil || got.Scheme != "https" || got.Host != "claude.ai" || got.Query().Get("code") == "" {
		t.Fatalf("consent redirect %q is not the client callback with a code", loc)
	}
}

func TestDuplicateConsentReturnsSameLocation(t *testing.T) {
	s, ts := testServer(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := dcrWithRedirect(t, ts, redirect)
	client, csrf, reqID := beginConsent(t, ts, clientID, redirect)
	firstStatus, firstLoc := postConsent(t, client, ts, csrf, reqID)
	secondStatus, secondLoc := postConsent(t, client, ts, csrf, reqID)
	if firstStatus != http.StatusOK || secondStatus != http.StatusOK {
		t.Fatalf("duplicate consent statuses %d, %d; want 200, 200", firstStatus, secondStatus)
	}
	if firstLoc == "" || firstLoc != secondLoc {
		t.Fatalf("duplicate consent must return identical Location, got %q and %q", firstLoc, secondLoc)
	}
	if n := countGrants(t, s); n != 1 {
		t.Fatalf("duplicate consent issued %d grants, want 1", n)
	}
}

func TestConcurrentConsentIssuesOneGrant(t *testing.T) {
	s, ts := testServer(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := dcrWithRedirect(t, ts, redirect)
	client, csrf, reqID := beginConsent(t, ts, clientID, redirect)
	cookies := jarCookies(client, ts.URL)
	const workers = 8
	statuses := make([]int, workers)
	locations := make([]string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := &http.Client{Jar: &simpleJar{cookies: cookies}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			status, loc := postConsent(t, c, ts, csrf, reqID)
			statuses[i], locations[i] = status, loc
		}(i)
	}
	wg.Wait()
	for i := 0; i < workers; i++ {
		if statuses[i] != http.StatusOK {
			t.Fatalf("worker %d status %d, want 200", i, statuses[i])
		}
		if locations[i] == "" || locations[i] != locations[0] {
			t.Fatalf("worker %d location %q differs from %q", i, locations[i], locations[0])
		}
	}
	if n := countGrants(t, s); n != 1 {
		t.Fatalf("concurrent consent issued %d grants, want 1", n)
	}
}

func jarCookies(client *http.Client, rawURL string) []*http.Cookie {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return append([]*http.Cookie(nil), client.Jar.Cookies(u)...)
}

func TestConsentRetryAfterExchangeIsInvalid(t *testing.T) {
	_, ts := testServer(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := dcrWithRedirect(t, ts, redirect)
	client, csrf, reqID := beginConsent(t, ts, clientID, redirect)
	_, loc := postConsent(t, client, ts, csrf, reqID)
	code := queryOf(loc).Get("code")
	if code == "" {
		t.Fatalf("no code in %q", loc)
	}
	verifier := strings.Repeat("v", 64)
	if status, _ := exchange(t, ts, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "resource": {testURL}, "code_verifier": {verifier},
	}); status != 200 {
		t.Fatalf("exchange: %d", status)
	}
	resp, err := client.PostForm(ts.URL+"/consent", url.Values{"csrf": {csrf}, "request": {reqID}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("retry after redemption must be invalid_request (400), got %d", resp.StatusCode)
	}
	if body := readAll(t, resp.Body); !strings.Contains(body, "invalid_request") {
		t.Fatalf("retry after redemption must report invalid_request, got %q", body)
	}
}

func TestExpiredConsentStaysInvalid(t *testing.T) {
	s, ts := testServer(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := dcrWithRedirect(t, ts, redirect)
	client, csrf, reqID := beginConsent(t, ts, clientID, redirect)
	if err := s.store.update(func(st *state) error {
		p := st.Pending[reqID]
		p.ExpiresAt = time.Now().UTC().Add(-time.Minute)
		st.Pending[reqID] = p
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		resp, err := client.PostForm(ts.URL+"/consent", url.Values{"csrf": {csrf}, "request": {reqID}})
		if err != nil {
			t.Fatal(err)
		}
		body := readAll(t, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 400 || !strings.Contains(body, "invalid_request") {
			t.Fatalf("expired consent attempt %d: %d %q, want 400 invalid_request", i, resp.StatusCode, body)
		}
	}
	if n := countGrants(t, s); n != 0 {
		t.Fatalf("expired consent issued %d grants, want 0", n)
	}
}
