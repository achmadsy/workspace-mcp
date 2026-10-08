package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/link/workspace-mcp/internal/limits"
	"golang.org/x/crypto/argon2"
)

type pageData struct {
	Title, Message, Action, CSRF, Request, Button string
	Password                                      bool
	// FormActionOrigin, when set, is added to form-action for the
	// cross-origin redirect that follows consent (the OAuth client
	// callback). Empty keeps the policy self-only.
	FormActionOrigin string
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirect := q.Get("redirect_uri")
	resource := q.Get("resource")
	scope := q.Get("scope")
	challenge := q.Get("code_challenge")
	if q.Get("response_type") != "code" || clientID == "" || resource != s.publicURL || !s.validScope(scope) || q.Get("code_challenge_method") != "S256" || challenge == "" {
		oauthError(w, 400, "invalid_request", "authorization request is invalid")
		return
	}
	var client Client
	ok := false
	_ = s.store.view(func(st *state) error { client, ok = st.Clients[clientID]; return nil })
	if !ok || !exactRedirect(client, redirect) {
		oauthError(w, 400, "invalid_request", "client or redirect URI is invalid")
		return
	}
	scope = s.grantedScope(scope)
	id, err := randomToken()
	if err != nil {
		http.Error(w, "authorization failed", 500)
		return
	}
	now := time.Now().UTC()
	p := PendingAuthorization{ID: id, ClientID: clientID, RedirectURI: redirect, Resource: resource, Scope: scope, State: q.Get("state"), CodeChallenge: challenge, CreatedAt: now, ExpiresAt: now.Add(limits.AuthorizationTTL)}
	if err := s.store.update(func(st *state) error { st.Pending[id] = p; return nil }); err != nil {
		http.Error(w, "authorization failed", 500)
		return
	}
	_, sess, err := s.ensureSession(w, r)
	if err != nil {
		http.Error(w, "session failed", 500)
		return
	}
	if !sess.Authenticated {
		http.Redirect(w, r, "/login?request="+url.QueryEscape(id), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/consent?request="+url.QueryEscape(id), http.StatusFound)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	_, sess, err := s.ensureSession(w, r)
	if err != nil {
		http.Error(w, "session failed", 500)
		return
	}
	id := r.URL.Query().Get("request")
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		id = r.Form.Get("request")
		if !secureEqual(sess.CSRF, r.Form.Get("csrf")) {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		if !s.loginLimiter.allow(clientIP(r), time.Now()) {
			http.Error(w, "too many attempts", 429)
			return
		}
		candidate := argon2.IDKey([]byte(r.Form.Get("password")), s.passwordSalt, 3, 64*1024, 2, 32)
		if subtleCompare(candidate, s.passwordHash) {
			sess.Authenticated = true
			sess.LastSeen = time.Now().UTC()
			_ = s.store.update(func(st *state) error { st.Sessions[sess.Hash] = sess; return nil })
			http.Redirect(w, r, "/consent?request="+url.QueryEscape(id), http.StatusFound)
			return
		}
		render(w, pageData{Title: "Workspace MCP login", Message: "Invalid password", Action: "/login", CSRF: sess.CSRF, Request: id, Button: "Sign in", Password: true})
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET, POST")
		return
	}
	render(w, pageData{Title: "Workspace MCP login", Action: "/login", CSRF: sess.CSRF, Request: id, Button: "Sign in", Password: true})
}

func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	_, sess, err := s.ensureSession(w, r)
	if err != nil {
		http.Error(w, "session failed", 500)
		return
	}
	if !sess.Authenticated {
		http.Redirect(w, r, "/login?request="+url.QueryEscape(r.URL.Query().Get("request")), 302)
		return
	}
	id := r.URL.Query().Get("request")
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		id = r.Form.Get("request")
		if !secureEqual(sess.CSRF, r.Form.Get("csrf")) {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		var p PendingAuthorization
		ok := false
		_ = s.store.view(func(st *state) error { p, ok = st.Pending[id]; return nil })
		if !ok || time.Now().After(p.ExpiresAt) {
			oauthError(w, 400, "invalid_request", "authorization request expired")
			return
		}
		code, _ := randomToken()
		grant := CodeGrant{Hash: hashToken(code), ClientID: p.ClientID, RedirectURI: p.RedirectURI, Resource: p.Resource, Scope: p.Scope, CodeChallenge: p.CodeChallenge, ExpiresAt: time.Now().UTC().Add(limits.AuthorizationTTL)}
		if err := s.store.update(func(st *state) error {
			delete(st.Pending, id)
			st.Codes[grant.Hash] = grant
			st.Consents[p.ClientID+"|"+p.Resource] = true
			return nil
		}); err != nil {
			http.Error(w, "consent failed", 500)
			return
		}
		u, _ := url.Parse(p.RedirectURI)
		q := u.Query()
		q.Set("code", code)
		if p.State != "" {
			q.Set("state", p.State)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), 302)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET, POST")
		return
	}
	var p PendingAuthorization
	var c Client
	ok := false
	_ = s.store.view(func(st *state) error { p, ok = st.Pending[id]; c = st.Clients[p.ClientID]; return nil })
	if !ok || time.Now().After(p.ExpiresAt) {
		oauthError(w, 400, "invalid_request", "authorization request expired")
		return
	}
	host := ""
	callbackOrigin := ""
	if u, e := url.Parse(p.RedirectURI); e == nil {
		host = u.Host
		callbackOrigin = u.Scheme + "://" + u.Host
	}
	render(w, pageData{Title: "Authorize workspace access", Message: "Client: " + c.ClientName + "; redirect host: " + host + "; scope: " + p.Scope + "; resource: " + p.Resource, Action: "/consent", CSRF: sess.CSRF, Request: id, Button: "Allow", FormActionOrigin: callbackOrigin})
}

func subtleCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
func pkceOK(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return secureEqual(base64.RawURLEncoding.EncodeToString(sum[:]), challenge)
}

// grantedScope returns the scope string recorded for an authorization request.
// Some OAuth clients (claude.ai among them) request only the base "workspace"
// scope and never ask for the optional ones, so a bare "workspace" request is
// expanded to every scope this server has enabled. The consent page prints the
// expanded list, so the operator approves it explicitly. A request that names
// any optional scope is kept exactly as asked.
func (s *Server) grantedScope(requested string) string {
	parts := strings.Fields(requested)
	if len(parts) == 1 && parts[0] == "workspace" {
		return strings.Join(s.scopes, " ")
	}
	return requested
}

func (s *Server) validScope(v string) bool {
	parts := strings.Fields(v)
	if len(parts) == 0 {
		return false
	}
	seen := make(map[string]bool, len(parts))
	for _, scope := range parts {
		if !s.scopeSet[scope] || seen[scope] {
			return false
		}
		seen[scope] = true
	}
	return seen["workspace"]
}
