package server

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/link/workspace-mcp/internal/auth"
	"github.com/link/workspace-mcp/internal/config"
	"github.com/link/workspace-mcp/internal/git"
	"github.com/link/workspace-mcp/internal/httpx"
	"github.com/link/workspace-mcp/internal/limits"
	"github.com/link/workspace-mcp/internal/sandboxexec"
	"github.com/link/workspace-mcp/internal/workspace"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wires configuration, workspace, git, auth, and MCP transport.
type Server struct {
	cfg  config.Config
	ws   *workspace.Root
	gs   *git.Service
	jobs *sandboxexec.Jobs
	auth *auth.Server
	srv  *mcp.Server
}

func New(cfg config.Config) (*Server, error) {
	ws, err := workspace.OpenRoot(cfg.WorkspaceRoot)
	if err != nil {
		return nil, err
	}
	runner, err := sandboxexec.New(cfg, ws)
	if err != nil {
		ws.Close()
		return nil, err
	}
	gs, err := git.NewAgentic(ws, runner)
	if err != nil {
		ws.Close()
		return nil, err
	}
	var jobs *sandboxexec.Jobs
	if cfg.EnableExec {
		jobs, err = sandboxexec.NewJobs(runner)
		if err != nil {
			gs.Close()
			ws.Close()
			return nil, err
		}
	}
	var store *auth.Store
	if cfg.Mode == config.ModePublic {
		store, err = auth.OpenStore(cfg.StateDir, cfg.StateKey, cfg.PublicURL)
		if err != nil {
			if jobs != nil {
				jobs.Close()
			}
			gs.Close()
			ws.Close()
			return nil, err
		}
	}
	enabledScopes := make([]string, 0, 3)
	if cfg.EnableExec {
		enabledScopes = append(enabledScopes, "workspace:exec")
	}
	if cfg.EnableGitWrite {
		enabledScopes = append(enabledScopes, "workspace:git-write")
	}
	if cfg.EnableGitNetwork {
		enabledScopes = append(enabledScopes, "workspace:git-network")
	}
	a, err := auth.NewServer(cfg.PublicURL, cfg.AdminPassword, store, enabledScopes...)
	if err != nil {
		if store != nil {
			store.Close()
		}
		if jobs != nil {
			jobs.Close()
		}
		gs.Close()
		ws.Close()
		return nil, err
	}
	s := &Server{cfg: cfg, ws: ws, gs: gs, jobs: jobs, auth: a}
	s.srv = mcp.NewServer(&mcp.Implementation{Name: "workspace-mcp", Version: "1.0.0"}, nil)
	registerTools(s.srv, cfg, ws, gs, runner, jobs)
	return s, nil
}

func (s *Server) Close() {
	_ = s.auth.Close()
	if s.jobs != nil {
		s.jobs.Close()
	}
	s.gs.Close()
	_ = s.ws.Close()
}

// handler builds the fully hardened HTTP surface.
func (s *Server) handler() http.Handler {
	root := http.NewServeMux()
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s.srv }, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true, // Quick Tunnels do not support SSE.
		MaxRequestBodyBytes:          limits.MaxRequestBody,
		PropagateRequestCancellation: true,
		// A trusted reverse tunnel connects from loopback while preserving the
		// public Host header. The SDK's localhost DNS-rebinding check would reject
		// that valid proxy shape; httpx origin protection remains active.
		DisableLocalhostProtection: s.cfg.Mode == config.ModePublic && s.cfg.TrustTunnel,
	})
	if s.cfg.Mode == config.ModePublic {
		s.auth.Register(root)
		protected := mcpauth.RequireBearerToken(s.auth.VerifyToken, &mcpauth.RequireBearerTokenOptions{
			Scopes:              []string{"workspace"},
			ResourceMetadataURL: s.auth.ProtectedResourceMetadataURL(),
		})(mcpHandler)
		root.Handle("/mcp", protected)
	} else {
		root.Handle("/mcp", mcpHandler)
	}
	return httpx.Harden(root, httpx.Config{
		PublicOrigin:       s.cfg.Origin(),
		OriginPaths:        []string{"/mcp", "/logout"},
		AllowedOrigins:     s.cfg.AllowedOrigins,
		TrustLoopbackProxy: s.cfg.TrustTunnel,
		MaxConcurrency:     limits.MaxHTTPConcurrency,
		RequestTimeout:     limits.HTTPTimeout,
	})
}

// Run serves until ctx is cancelled, then drains in-flight requests.
func (s *Server) Run(ctx context.Context) error {
	httpSrv := &http.Server{
		Addr:              s.cfg.Address(),
		Handler:           s.handler(),
		ReadHeaderTimeout: limits.HTTPHeaderTimeout,
		IdleTimeout:       limits.SessionIdleTTL,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), limits.ShutdownTimeout)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}
