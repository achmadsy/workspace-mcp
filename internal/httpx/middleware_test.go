package httpx

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func passthrough() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
}

func TestOriginValidation(t *testing.T) {
	h := Harden(passthrough(), Config{PublicOrigin: "https://mcp.example.com"})
	req := httptest.NewRequest("POST", "http://x/mcp", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("bad origin must 403, got %d", rec.Code)
	}
	req2 := httptest.NewRequest("POST", "http://x/mcp", nil) // no Origin: allowed (server-to-server)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("no origin must pass, got %d", rec2.Code)
	}
	req3 := httptest.NewRequest("POST", "http://x/mcp", nil)
	req3.Header.Set("Origin", "https://mcp.example.com")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != 200 {
		t.Fatalf("public origin must pass, got %d", rec3.Code)
	}
}

func TestPanicRecovery(t *testing.T) {
	h := Harden(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }), Config{Logger: slog.Default()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != 500 {
		t.Fatalf("panic must yield 500, got %d", rec.Code)
	}
}

func TestRateLimit(t *testing.T) {
	h := Harden(passthrough(), Config{})
	code := 200
	for i := 0; i < 300; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "http://x/", nil))
		code = rec.Code
		if code != 200 {
			t.Fatalf("request %d should pass", i)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://x/", nil))
	if rec.Code != 429 {
		t.Fatalf("301st request must be limited, got %d", rec.Code)
	}
}

func TestRequestTimeout(t *testing.T) {
	canceled := false
	h := Harden(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			canceled = true
		case <-time.After(time.Second):
		}
	}), Config{RequestTimeout: 10 * time.Millisecond})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://x/", nil))
	if !canceled {
		t.Fatal("handler must observe cancelled context")
	}
}
