package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/link/workspace-mcp/internal/limits"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
)

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		oauthError(w, 400, "invalid_request", "form-encoded request required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "invalid form")
		return
	}
	if r.Form.Get("resource") != s.publicURL {
		oauthError(w, 400, "invalid_target", "resource is required and must exactly match")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r)
	case "refresh_token":
		s.exchangeRefresh(w, r)
	default:
		oauthError(w, 400, "unsupported_grant_type", "unsupported grant type")
	}
}
func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	h := hashToken(code)
	var g CodeGrant
	ok := false
	_ = s.store.view(func(st *state) error { g, ok = st.Codes[h]; return nil })
	if !ok || time.Now().After(g.ExpiresAt) || g.ClientID != r.Form.Get("client_id") || g.RedirectURI != r.Form.Get("redirect_uri") || g.Resource != r.Form.Get("resource") || !pkceOK(r.Form.Get("code_verifier"), g.CodeChallenge) {
		oauthError(w, 400, "invalid_grant", "authorization code is invalid")
		return
	}
	access, refresh, family, err := newTokenTriple()
	if err != nil {
		http.Error(w, "token generation failed", 500)
		return
	}
	now := time.Now().UTC()
	if err := s.store.update(func(st *state) error {
		if _, exists := st.Codes[h]; !exists {
			return errors.New("code replay")
		}
		delete(st.Codes, h)
		st.Access[hashToken(access)] = TokenRecord{Hash: hashToken(access), ClientID: g.ClientID, Resource: g.Resource, Scope: g.Scope, Family: family, ExpiresAt: now.Add(limits.AccessTokenTTL)}
		st.Refresh[hashToken(refresh)] = RefreshRecord{Hash: hashToken(refresh), ClientID: g.ClientID, Resource: g.Resource, Scope: g.Scope, Family: family, ExpiresAt: now.Add(limits.RefreshTokenTTL)}
		return nil
	}); err != nil {
		oauthError(w, 400, "invalid_grant", "authorization code is invalid")
		return
	}
	tokenResponse(w, access, refresh)
}
func (s *Server) exchangeRefresh(w http.ResponseWriter, r *http.Request) {
	h := hashToken(r.Form.Get("refresh_token"))
	access, err := randomToken()
	if err != nil {
		http.Error(w, "token generation failed", 500)
		return
	}
	refresh, err := randomToken()
	if err != nil {
		http.Error(w, "token generation failed", 500)
		return
	}
	now := time.Now().UTC()
	replay := false
	err = s.store.update(func(st *state) error {
		old, ok := st.Refresh[h]
		if !ok || now.After(old.ExpiresAt) || old.ClientID != r.Form.Get("client_id") || old.Resource != r.Form.Get("resource") || st.RevokedFamilies[old.Family] {
			return errors.New("invalid")
		}
		if old.Used {
			st.RevokedFamilies[old.Family] = true
			replay = true
			return nil
		}
		old.Used = true
		st.Refresh[h] = old
		st.Access[hashToken(access)] = TokenRecord{Hash: hashToken(access), ClientID: old.ClientID, Resource: old.Resource, Scope: old.Scope, Family: old.Family, ExpiresAt: now.Add(limits.AccessTokenTTL)}
		st.Refresh[hashToken(refresh)] = RefreshRecord{Hash: hashToken(refresh), ClientID: old.ClientID, Resource: old.Resource, Scope: old.Scope, Family: old.Family, ExpiresAt: now.Add(limits.RefreshTokenTTL)}
		return nil
	})
	if err != nil || replay {
		oauthError(w, 400, "invalid_grant", "refresh token is invalid")
		return
	}
	tokenResponse(w, access, refresh)
}
func newTokenTriple() (string, string, string, error) {
	a, e := randomToken()
	if e != nil {
		return "", "", "", e
	}
	r, e := randomToken()
	if e != nil {
		return "", "", "", e
	}
	f, e := randomToken()
	return a, r, f, e
}
func tokenResponse(w http.ResponseWriter, a, r string) {
	writeJSON(w, 200, map[string]any{"access_token": a, "token_type": "Bearer", "expires_in": int(limits.AccessTokenTTL.Seconds()), "refresh_token": r, "scope": "workspace"})
}
func (s *Server) VerifyToken(ctx context.Context, raw string, req *http.Request) (*mcpauth.TokenInfo, error) {
	h := hashToken(raw)
	var rec TokenRecord
	ok := false
	revoked := false
	_ = s.store.view(func(st *state) error { rec, ok = st.Access[h]; revoked = st.RevokedFamilies[rec.Family]; return nil })
	if !ok || revoked || time.Now().After(rec.ExpiresAt) || rec.Resource != s.publicURL {
		return nil, mcpauth.ErrInvalidToken
	}
	return &mcpauth.TokenInfo{Scopes: []string{rec.Scope}, Expiration: rec.ExpiresAt, UserID: "workspace-owner"}, nil
}
