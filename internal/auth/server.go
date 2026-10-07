// Package auth implements embedded single-user OAuth 2.1 authorization.
package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

type Server struct {
	publicURL, origin string
	store             *Store
	passwordSalt      []byte
	passwordHash      []byte
	loginLimiter      *attemptLimiter
	scopes            []string
	scopeSet          map[string]bool
}

func NewServer(publicURL, password string, store *Store, enabledScopes ...string) (*Server, error) {
	salt := []byte("workspace-mcp-admin-password-v1")
	var hash []byte
	if store != nil {
		hash = argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	}
	scopes := []string{"workspace"}
	seen := map[string]bool{"workspace": true}
	for _, scope := range enabledScopes {
		if scope != "" && !seen[scope] {
			scopes = append(scopes, scope)
			seen[scope] = true
		}
	}
	return &Server{
		publicURL:    publicURL,
		origin:       strings.TrimSuffix(publicURL, "/mcp"),
		store:        store,
		passwordSalt: salt,
		passwordHash: hash,
		loginLimiter: newAttemptLimiter(),
		scopes:       scopes,
		scopeSet:     seen,
	}, nil
}

func (s *Server) Close() error {
	if s.store == nil {
		return nil
	}
	return s.store.Close()
}

// ProtectedResourceMetadataURL is the path-specific RFC 9728 metadata URL.
func (s *Server) ProtectedResourceMetadataURL() string {
	return s.origin + "/.well-known/oauth-protected-resource/mcp"
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", s.protectedMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.protectedMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.authorizationMetadata)
	mux.HandleFunc("/register", s.register)
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/consent", s.consent)
	mux.HandleFunc("/logout", s.logout)
}

type attemptLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newAttemptLimiter() *attemptLimiter {
	return &attemptLimiter{attempts: map[string][]time.Time{}}
}

func (l *attemptLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-time.Minute)
	old := l.attempts[key]
	keep := old[:0]
	for _, t := range old {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= 5 {
		l.attempts[key] = keep
		return false
	}
	l.attempts[key] = append(keep, now)
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
