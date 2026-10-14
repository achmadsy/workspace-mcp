package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/link/workspace-mcp/internal/limits"
	"golang.org/x/crypto/argon2"
)

var (
	errAuthorizationExpired = errors.New("authorization request expired")
	errAuthorizationGranted = errors.New("authorization already granted")
)

type pageData struct {
	Title, Message, Action, CSRF, Request, Button string
	Password                                      bool
	// FormActionOrigins are exact origins permitted for form submission.
	FormActionOrigins []string
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
			http.Redirect(w, r, "/consent?request="+url.QueryEscape(id), http.StatusSeeOther)
			return
		}
		render(w, pageData{Title: "Workspace MCP login", Message: "Invalid password", Action: "/login", CSRF: sess.CSRF, Request: id, Button: "Sign in", Password: true, FormActionOrigins: []string{s.origin}})
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET, POST")
		return
	}
	render(w, pageData{Title: "Workspace MCP login", Action: "/login", CSRF: sess.CSRF, Request: id, Button: "Sign in", Password: true, FormActionOrigins: []string{s.origin}})
}

func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	_, sess, err := s.ensureSession(w, r)
	if err != nil {
		http.Error(w, "session failed", 500)
		return
	}
	if !sess.Authenticated {
		http.Redirect(w, r, "/login?request="+url.QueryEscape(r.URL.Query().Get("request")), http.StatusFound)
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
		if !ok || time.Now().UTC().After(p.ExpiresAt) {
			oauthError(w, 400, "invalid_request", "authorization request expired")
			return
		}
		if p.Location != "" {
			// Retry-safe: a grant already exists for this request, so render the
			// identical callback without issuing a second grant.
			renderCompletion(w, p.Location)
			return
		}
		code, err := randomToken()
		if err != nil {
			http.Error(w, "consent failed", 500)
			return
		}
		u, err := url.Parse(p.RedirectURI)
		if err != nil {
			oauthError(w, 400, "invalid_request", "authorization request expired")
			return
		}
		q := u.Query()
		q.Set("code", code)
		if p.State != "" {
			q.Set("state", p.State)
		}
		u.RawQuery = q.Encode()
		location := u.String()
		codeHash := hashToken(code)
		grant := CodeGrant{Hash: codeHash, ClientID: p.ClientID, RedirectURI: p.RedirectURI, Resource: p.Resource, Scope: p.Scope, CodeChallenge: p.CodeChallenge, ExpiresAt: time.Now().UTC().Add(limits.AuthorizationTTL), PendingID: id}
		err = s.store.update(func(st *state) error {
			current, exists := st.Pending[id]
			if !exists || time.Now().UTC().After(current.ExpiresAt) {
				return errAuthorizationExpired
			}
			if current.Location != "" {
				location = current.Location
				return errAuthorizationGranted
			}
			current.CodeHash = codeHash
			current.Location = location
			st.Pending[id] = current
			st.Codes[codeHash] = grant
			st.Consents[current.ClientID+"|"+current.Resource] = true
			return nil
		})
		if errors.Is(err, errAuthorizationGranted) {
			renderCompletion(w, location)
			return
		}
		if errors.Is(err, errAuthorizationExpired) {
			oauthError(w, 400, "invalid_request", "authorization request expired")
			return
		}
		if err != nil {
			http.Error(w, "consent failed", 500)
			return
		}
		renderCompletion(w, location)
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
	if u, e := url.Parse(p.RedirectURI); e == nil {
		host = u.Host
	}
	render(w, pageData{Title: "Authorize workspace access", Message: "Client: " + c.ClientName + "; redirect host: " + host + "; scope: " + p.Scope + "; resource: " + p.Resource, Action: "/consent", CSRF: sess.CSRF, Request: id, Button: "Allow", FormActionOrigins: []string{s.origin}})
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
