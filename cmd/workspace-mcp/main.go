// Command workspace-mcp serves a sandboxed workspace over MCP Streamable HTTP.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/link/workspace-mcp/internal/config"
	"github.com/link/workspace-mcp/internal/server"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("workspace-mcp exited", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("workspace-mcp listening",
		"address", cfg.Address(),
		"mode", cfg.Mode,
		"workspace_root", cfg.WorkspaceRoot,
	)
	if cfg.Mode == config.ModePublic {
		logger.Info("public endpoint", "mcp_url", cfg.PublicURL)
	} else {
		logger.Info("local mode: no authentication; bind is loopback and any data is reachable by local processes")
	}
	return srv.Run(ctx)
}
