#!/bin/sh
# Start workspace-mcp. Usage: ./scripts/start.sh /path/to/workspace
# Reads all configuration from the environment (see .env.example).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -n "$1" ]; then
  WORKSPACE_ROOT="$1"
fi
if [ -z "$WORKSPACE_ROOT" ]; then
  echo "usage: $0 /path/to/workspace  (or export WORKSPACE_ROOT)" >&2
  exit 1
fi
export WORKSPACE_ROOT

export MCP_HOST="${MCP_HOST:-127.0.0.1}"
export MCP_PORT="${MCP_PORT:-8787}"
export MCP_MODE="${MCP_MODE:-local}"

if [ "$MCP_MODE" = "public" ]; then
  : "${MCP_PUBLIC_URL:?MCP_PUBLIC_URL is required in public mode}"
  : "${MCP_ADMIN_PASSWORD:?MCP_ADMIN_PASSWORD is required in public mode}"
  : "${MCP_STATE_DIR:?MCP_STATE_DIR is required in public mode}"
  : "${MCP_STATE_KEY:?MCP_STATE_KEY is required in public mode}"
fi

# Build if needed using the project-local toolchain.
if [ ! -x "$ROOT/bin/workspace-mcp" ] || [ -n "$FORCE_BUILD" ]; then
  "$ROOT/scripts/bootstrap-go.sh"
  GOROOT="$ROOT/.tools/go" PATH="$ROOT/.tools/go/bin:$PATH" \
    "$ROOT/.tools/go/bin/go" build -o "$ROOT/bin/workspace-mcp" ./cmd/workspace-mcp
fi

exec "$ROOT/bin/workspace-mcp"
