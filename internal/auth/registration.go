package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	var in registrationRequest
	if dec.Decode(&in) != nil || len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > 8 {
		oauthError(w, 400, "invalid_client_metadata", "invalid registration document")
		return
	}
	if in.TokenEndpointAuthMethod != "" && in.TokenEndpointAuthMethod != "none" {
		oauthError(w, 400, "invalid_client_metadata", "only public clients are supported")
		return
	}
	if len(in.GrantTypes) > 0 && (!contains(in.GrantTypes, "authorization_code") || !onlyContains(in.GrantTypes, "authorization_code", "refresh_token")) {
		oauthError(w, 400, "invalid_client_metadata", "unsupported grant types")
		return
	}
	if len(in.ResponseTypes) > 0 && !onlyContains(in.ResponseTypes, "code") {
		oauthError(w, 400, "invalid_client_metadata", "unsupported response types")
		return
	}
	for _, raw := range in.RedirectURIs {
		if !validRedirect(raw) {
			oauthError(w, 400, "invalid_redirect_uri", "redirect URI is invalid")
			return
		}
	}
	id, err := randomToken()
	if err != nil {
		http.Error(w, "registration failed", 500)
		return
	}
	client := Client{ClientID: id, ClientName: strings.TrimSpace(in.ClientName), RedirectURIs: append([]string(nil), in.RedirectURIs...), CreatedAt: time.Now().UTC()}
	if client.ClientName == "" {
		client.ClientName = "MCP client"
	}
	if err := s.store.update(func(st *state) error { st.Clients[id] = client; return nil }); err != nil {
		http.Error(w, "registration failed", 500)
		return
	}
	writeJSON(w, 201, map[string]any{"client_id": id, "client_name": client.ClientName, "redirect_uris": client.RedirectURIs, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
}
func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() == false || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Host == "" || u.Hostname() == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost") && u.Path == "/callback"
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func onlyContains(values []string, allowed ...string) bool {
	for _, value := range values {
		if !contains(allowed, value) {
			return false
		}
	}
	return true
}
func exactRedirect(c Client, raw string) bool {
	for _, v := range c.RedirectURIs {
		if v == raw {
			return true
		}
	}
	return false
}
