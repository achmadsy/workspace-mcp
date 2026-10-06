package auth

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"time"

	"github.com/link/workspace-mcp/internal/limits"
)

const sessionCookie = "workspace_mcp_session"

var page = template.Must(template.New("page").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{{.Title}}</title></head><body><main><h1>{{.Title}}</h1>{{if .Message}}<p>{{.Message}}</p>{{end}}<form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="request" value="{{.Request}}">{{if .Password}}<label>Password <input type="password" name="password" required autocomplete="current-password"></label>{{end}}<button type="submit">{{.Button}}</button></form></main></body></html>`))

func (s *Server) ensureSession(w http.ResponseWriter, r *http.Request) (string, BrowserSession, error) {
	now := time.Now().UTC()
	if c, err := r.Cookie(sessionCookie); err == nil {
		h := hashToken(c.Value)
		var found BrowserSession
		ok := false
		_ = s.store.view(func(st *state) error { found, ok = st.Sessions[h]; return nil })
		if ok && now.Before(found.ExpiresAt) && now.Sub(found.LastSeen) <= limits.SessionIdleTTL {
			found.LastSeen = now
			_ = s.store.update(func(st *state) error { st.Sessions[h] = found; return nil })
			return c.Value, found, nil
		}
	}
	token, err := randomToken()
	if err != nil {
		return "", BrowserSession{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", BrowserSession{}, err
	}
	sess := BrowserSession{Hash: hashToken(token), CSRF: csrf, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(limits.SessionAbsoluteTTL)}
	if err := s.store.update(func(st *state) error { st.Sessions[sess.Hash] = sess; return nil }); err != nil {
		return "", BrowserSession{}, err
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(limits.SessionAbsoluteTTL.Seconds())})
	return token, sess, nil
}
func secureEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func render(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	if err := page.Execute(w, data); err != nil {
		http.Error(w, "render failed", 500)
	}
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.store.update(func(st *state) error { delete(st.Sessions, hashToken(c.Value)); return nil })
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}
