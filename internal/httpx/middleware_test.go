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
	h := Harden(passthrough(), Config{
		PublicOrigin:   "https://mcp.example.com",
		OriginPaths:    []string{"/mcp", "/logout"},
		AllowedOrigins: []string{"https://claude.ai", "https://claude.com", "https://gemini.google.com", "https://chatgpt.com", "https://www.kimi.com", "https://chat.qwen.ai", "https://chat.z.ai"},
	})
	tests := []struct {
		name   string
		path   string
		origin string
		want   int
	}{
		{name: "foreign MCP origin", path: "/mcp", origin: "https://evil.example.com", want: 403},
		{name: "no MCP origin", path: "/mcp", want: 200},
		{name: "public MCP origin", path: "/mcp", origin: "https://mcp.example.com", want: 200},
		{name: "claude.ai MCP origin", path: "/mcp", origin: "https://claude.ai", want: 200},
		{name: "claude.ai default port", path: "/mcp", origin: "https://claude.ai:443", want: 200},
		{name: "claude.com MCP origin", path: "/mcp", origin: "https://claude.com", want: 200},
		{name: "gemini MCP origin", path: "/mcp", origin: "https://gemini.google.com", want: 200},
		{name: "chatgpt MCP origin", path: "/mcp", origin: "https://chatgpt.com", want: 200},
		{name: "kimi MCP origin", path: "/mcp", origin: "https://www.kimi.com", want: 200},
		{name: "qwen MCP origin", path: "/mcp", origin: "https://chat.qwen.ai", want: 200},
		{name: "z.ai MCP origin", path: "/mcp", origin: "https://chat.z.ai", want: 200},
		{name: "gemini lookalike", path: "/mcp", origin: "https://gemini.google.com.evil.example.com", want: 403},
		{name: "chatgpt lookalike", path: "/mcp", origin: "https://evil-chatgpt.com", want: 403},
		{name: "kimi bare domain", path: "/mcp", origin: "https://kimi.com", want: 403},
		{name: "qwen lookalike", path: "/mcp", origin: "https://chat.qwen.ai.evil.example.com", want: 403},
		{name: "z.ai lookalike", path: "/mcp", origin: "https://evil-chat.z.ai", want: 403},
		{name: "public origin default port", path: "/mcp", origin: "https://mcp.example.com:443", want: 200},
		{name: "claude.ai custom port", path: "/mcp", origin: "https://claude.ai:8443", want: 403},
		{name: "lookalike MCP origin", path: "/mcp", origin: "https://evil-claude.ai", want: 403},
		{name: "foreign login origin", path: "/login", origin: "https://claude.ai", want: 200},
		{name: "foreign consent origin", path: "/consent", origin: "https://claude.ai", want: 200},
		{name: "allowed logout origin", path: "/logout", origin: "https://claude.ai", want: 200},
		{name: "foreign logout origin", path: "/logout", origin: "https://evil.example.com", want: 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://x"+tt.path, nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status %d, want %d", rec.Code, tt.want)
			}
		})
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
