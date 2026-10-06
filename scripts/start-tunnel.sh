#!/bin/sh
# Start a Cloudflare Quick Tunnel and workspace-mcp with the generated URL.
#
# Usage: MCP_ADMIN_PASSWORD=... MCP_STATE_DIR=... MCP_STATE_KEY=... \
#          ./scripts/start-tunnel.sh /path/to/workspace
#
# Quick Tunnel URLs are TEMPORARY: every run generates a new *.trycloudflare.com
# host, so you must re-add the connector URL in Claude.ai after each restart.
# For a stable hostname use a named tunnel (see README "Named Tunnel").
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -n "$1" ]; then
  WORKSPACE_ROOT="$1"
fi
if [ -z "$WORKSPACE_ROOT" ]; then
  echo "usage: $0 /path/to/workspace" >&2
  exit 1
fi
export WORKSPACE_ROOT
export MCP_MODE=public
export MCP_HOST="${MCP_HOST:-127.0.0.1}"
export MCP_PORT="${MCP_PORT:-8787}"
: "${MCP_ADMIN_PASSWORD:?MCP_ADMIN_PASSWORD is required}"
: "${MCP_STATE_DIR:?MCP_STATE_DIR is required}"
: "${MCP_STATE_KEY:?MCP_STATE_KEY is required (openssl rand -base64 32)}"

command -v cloudflared >/dev/null 2>&1 || { echo "cloudflared not found; see README" >&2; exit 1; }

# Build first so the server is ready when the tunnel URL appears.
FORCE_BUILD=1 "$ROOT/scripts/bootstrap-go.sh" >/dev/null 2>&1 || true
GOROOT="$ROOT/.tools/go" PATH="$ROOT/.tools/go/bin:$PATH" \
  "$ROOT/.tools/go/bin/go" build -o "$ROOT/bin/workspace-mcp" ./cmd/workspace-mcp

TUNNEL_LOG="$(mktemp /tmp/workspace-mcp-tunnel.XXXXXX.log)"
cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
  [ -n "${TUNNEL_PID:-}" ] && kill "$TUNNEL_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "Starting Quick Tunnel (log: $TUNNEL_LOG)..."
cloudflared tunnel --url "http://127.0.0.1:$MCP_PORT" --no-autoupdate > "$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!

echo "Waiting for tunnel URL..."
TUNNEL_URL=""
i=0
while [ $i -lt 60 ]; do
  TUNNEL_URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$TUNNEL_LOG" | head -n1 || true)"
  [ -n "$TUNNEL_URL" ] && break
  if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
    echo "cloudflared exited unexpectedly; last log lines:" >&2
    tail -20 "$TUNNEL_LOG" >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 1
done
if [ -z "$TUNNEL_URL" ]; then
  echo "tunnel URL did not appear; log: $TUNNEL_LOG" >&2
  exit 1
fi

export MCP_PUBLIC_URL="$TUNNEL_URL/mcp"
echo ""
echo "==============================================================="
echo "  Claude.ai connector URL (exact):"
echo "  $MCP_PUBLIC_URL"
echo ""
echo "  Quick Tunnel URLs change on every restart."
echo "  Press Ctrl+C to stop both tunnel and server."
echo "==============================================================="
echo ""

"$ROOT/bin/workspace-mcp" &
SERVER_PID=$!
wait "$SERVER_PID"
