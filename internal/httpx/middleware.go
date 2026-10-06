// Package httpx supplies HTTP hardening without logging sensitive data.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Logger             *slog.Logger
	PublicOrigin       string
	TrustLoopbackProxy bool
	MaxConcurrency     int
	RequestTimeout     time.Duration
}
type chain struct {
	next  http.Handler
	cfg   Config
	sem   chan struct{}
	mu    sync.Mutex
	rates map[string]*rate
}
type rate struct {
	start time.Time
	count int
}
type requestIDKey struct{}

func RequestID(ctx context.Context) string { v, _ := ctx.Value(requestIDKey{}).(string); return v }

func Harden(next http.Handler, cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 32
	}
	return &chain{next: next, cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrency), rates: map[string]*rate{}}
}
func (h *chain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	}
	id := requestID()
	r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
	w.Header().Set("X-Request-ID", id)
	h.security(w)
	defer func() {
		if recover() != nil {
			h.cfg.Logger.Error("request panic", "request_id", id, "stack", string(debug.Stack()))
			http.Error(w, "internal server error", 500)
		}
	}()
	if !h.validOrigin(r) {
		http.Error(w, "forbidden origin", 403)
		return
	}
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	default:
		http.Error(w, "server busy", 503)
		return
	}
	ip := h.remoteIP(r)
	if !h.allow(ip, time.Now()) {
		http.Error(w, "rate limit exceeded", 429)
		return
	}
	ctx := r.Context()
	var cancel context.CancelFunc
	if h.cfg.RequestTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, h.cfg.RequestTimeout)
		defer cancel()
		r = r.WithContext(ctx)
	}
	start := time.Now()
	rw := &statusWriter{ResponseWriter: w, status: 200}
	h.next.ServeHTTP(rw, r)
	h.cfg.Logger.Info("http request", "request_id", id, "method", r.Method, "path", r.URL.Path, "status", rw.status, "duration_ms", time.Since(start).Milliseconds(), "remote_ip", ip)
}
func (h *chain) security(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Cache-Control", "no-store")
}
func (h *chain) validOrigin(r *http.Request) bool {
	raw := r.Header.Get("Origin")
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path != "" && u.Path != "/" {
		return false
	}
	origin := u.Scheme + "://" + u.Host
	if h.cfg.PublicOrigin != "" {
		return origin == h.cfg.PublicOrigin
	}
	return (u.Scheme == "http" || u.Scheme == "https") && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost")
}
func (h *chain) remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if h.cfg.TrustLoopbackProxy && ip != nil && ip.IsLoopback() {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(cf) != nil {
			return cf
		}
	}
	return host
}
func (h *chain) allow(key string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := h.rates[key]
	if v == nil || now.Sub(v.start) >= time.Minute {
		h.rates[key] = &rate{start: now, count: 1}
		return true
	}
	if v.count >= 300 {
		return false
	}
	v.count++
	return true
}
func requestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int)        { w.status = code; w.ResponseWriter.WriteHeader(code) }
func (w *statusWriter) Write(p []byte) (int, error) { return w.ResponseWriter.Write(p) }
