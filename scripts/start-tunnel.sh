#!/bin/sh
# Start a Cloudflare Quick Tunnel and workspace-mcp with secure persistent OAuth
# credentials. Usage: ./scripts/start-tunnel.sh [--fg] /path/to/workspace
#
# Default: the launcher re-executes itself inside a detached tmux session
# (name: workspace-mcp-tunnel) and returns immediately. Use --fg to run in the
# calling terminal instead (Ctrl+C stops tunnel and server).
set -e
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FOREGROUND=false
WORKSPACE_ROOT=""
SESSION_NAME="${WORKSPACE_MCP_SESSION:-workspace-mcp-tunnel}"
for arg in "$@"; do
  case "$arg" in
    --fg|--foreground) FOREGROUND=true ;;
    *) if [ -z "$WORKSPACE_ROOT" ]; then WORKSPACE_ROOT="$arg"; fi ;;
  esac
done
if [ -z "$WORKSPACE_ROOT" ]; then
  WORKSPACE_ROOT="${WORKSPACE_ROOT:-}"
fi
if [ -z "$WORKSPACE_ROOT" ]; then
  echo "usage: $0 [--fg] /path/to/workspace" >&2
  exit 1
fi
if [ ! -d "$WORKSPACE_ROOT" ]; then
  echo "workspace does not exist or is not a directory: $WORKSPACE_ROOT" >&2
  exit 1
fi
WORKSPACE_ROOT="$(cd "$WORKSPACE_ROOT" && pwd)"
export WORKSPACE_ROOT

if [ "$FOREGROUND" != true ] && [ -z "${TMUX:-}" ]; then
  if command -v tmux >/dev/null 2>&1; then
    if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
      echo "workspace-mcp is already running in tmux session '$SESSION_NAME'."
      echo "Attach:  tmux attach -t $SESSION_NAME"
      echo "Stop:    tmux kill-session -t $SESSION_NAME"
      exit 0
    fi
    tmux new-session -d -s "$SESSION_NAME" "exec '$0' --fg '$WORKSPACE_ROOT'"
    echo "Started in tmux session '$SESSION_NAME' (stays running when you log out of this shell)."
    echo "Attach:  tmux attach -t $SESSION_NAME"
    echo "Stop:    tmux kill-session -t $SESSION_NAME"
    exit 0
  fi
  echo "tmux not found; running in foreground instead (Ctrl+C stops everything)." >&2
fi

for command_name in cloudflared openssl curl python3 sha256sum tar; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name not found; install it before starting the Quick Tunnel" >&2
    exit 1
  }
done

export MCP_MODE=public
export MCP_HOST=127.0.0.1
export MCP_PORT="${MCP_PORT:-8787}"
export MCP_TRUST_CLOUDFLARE_TUNNEL="${MCP_TRUST_CLOUDFLARE_TUNNEL:-true}"
case "$MCP_PORT" in
  ''|*[!0-9]*) echo "MCP_PORT must be an integer from 1 to 65535" >&2; exit 1 ;;
esac
if [ "$MCP_PORT" -lt 1 ] || [ "$MCP_PORT" -gt 65535 ]; then
  echo "MCP_PORT must be an integer from 1 to 65535" >&2
  exit 1
fi

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
export MCP_STATE_DIR="${MCP_STATE_DIR:-$DATA_HOME/workspace-mcp}"
CREDENTIAL_FILE="$MCP_STATE_DIR/quick-tunnel.env"
mkdir -p "$MCP_STATE_DIR"
chmod 0700 "$MCP_STATE_DIR"

ENV_PASSWORD="${MCP_ADMIN_PASSWORD:-}"
ENV_KEY="${MCP_STATE_KEY:-}"
FILE_PASSWORD=""
FILE_KEY=""
LEGACY_CREDENTIALS=false
if [ -e "$CREDENTIAL_FILE" ]; then
  if [ -L "$CREDENTIAL_FILE" ] || [ ! -f "$CREDENTIAL_FILE" ]; then
    echo "credential path must be a regular file, not a symlink: $CREDENTIAL_FILE" >&2
    exit 1
  fi
  chmod 0600 "$CREDENTIAL_FILE"
  FILE_PASSWORD_B64="$(sed -n 's/^MCP_ADMIN_PASSWORD_B64=//p' "$CREDENTIAL_FILE")"
  if [ -n "$FILE_PASSWORD_B64" ]; then
    FILE_PASSWORD="$(printf '%s' "$FILE_PASSWORD_B64" | openssl base64 -d -A 2>/dev/null || true)"
  else
    FILE_PASSWORD="$(sed -n "s/^MCP_ADMIN_PASSWORD='\([^']*\)'$/\1/p" "$CREDENTIAL_FILE")"
    [ -n "$FILE_PASSWORD" ] && LEGACY_CREDENTIALS=true
  fi
  FILE_KEY="$(sed -n "s/^MCP_STATE_KEY='\([^']*\)'$/\1/p" "$CREDENTIAL_FILE")"
  if [ -z "$FILE_KEY" ]; then
    FILE_KEY="$(sed -n 's/^MCP_STATE_KEY=//p' "$CREDENTIAL_FILE")"
  fi
fi

MCP_ADMIN_PASSWORD="${ENV_PASSWORD:-$FILE_PASSWORD}"
MCP_STATE_KEY="${ENV_KEY:-$FILE_KEY}"
WRITE_CREDENTIALS=false
if [ -n "$ENV_PASSWORD" ] && [ "$ENV_PASSWORD" != "$FILE_PASSWORD" ]; then
  WRITE_CREDENTIALS=true
fi
if [ -n "$ENV_KEY" ] && [ "$ENV_KEY" != "$FILE_KEY" ]; then
  WRITE_CREDENTIALS=true
fi
if [ -z "$MCP_ADMIN_PASSWORD" ]; then
  MCP_ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '\n')"
  WRITE_CREDENTIALS=true
fi
if [ -z "$MCP_STATE_KEY" ]; then
  MCP_STATE_KEY="$(openssl rand -base64 32 | tr -d '\n')"
  WRITE_CREDENTIALS=true
fi
if [ "${#MCP_ADMIN_PASSWORD}" -lt 12 ]; then
  echo "MCP_ADMIN_PASSWORD must be at least 12 characters" >&2
  exit 1
fi
KEY_CHECK="$(mktemp /tmp/workspace-mcp-key.XXXXXX)"
if ! printf '%s' "$MCP_STATE_KEY" | openssl base64 -d -A -out "$KEY_CHECK" 2>/dev/null || [ "$(wc -c < "$KEY_CHECK" | tr -d ' ')" -ne 32 ]; then
  rm -f "$KEY_CHECK"
  echo "MCP_STATE_KEY must be base64 encoding of exactly 32 random bytes" >&2
  exit 1
fi
rm -f "$KEY_CHECK"
export MCP_ADMIN_PASSWORD MCP_STATE_KEY

if [ ! -e "$CREDENTIAL_FILE" ] || [ "$WRITE_CREDENTIALS" = true ] || [ "$LEGACY_CREDENTIALS" = true ]; then
  CREDENTIAL_TMP="$(mktemp "$MCP_STATE_DIR/.quick-tunnel.env.XXXXXX")"
  PASSWORD_B64="$(printf '%s' "$MCP_ADMIN_PASSWORD" | openssl base64 -A)"
  {
    printf 'MCP_ADMIN_PASSWORD_B64=%s\n' "$PASSWORD_B64"
    printf 'MCP_STATE_KEY=%s\n' "$MCP_STATE_KEY"
  } > "$CREDENTIAL_TMP"
  chmod 0600 "$CREDENTIAL_TMP"
  mv "$CREDENTIAL_TMP" "$CREDENTIAL_FILE"
fi

"$ROOT/scripts/bootstrap-go.sh"
GOROOT="$ROOT/.tools/go" PATH="$ROOT/.tools/go/bin:$PATH" \
  "$ROOT/.tools/go/bin/go" build -o "$ROOT/bin/workspace-mcp" ./cmd/workspace-mcp

TUNNEL_LOG="$(mktemp /tmp/workspace-mcp-tunnel.XXXXXX.log)"
cleanup() {
  trap - EXIT INT TERM
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
  [ -n "${TUNNEL_PID:-}" ] && kill "$TUNNEL_PID" 2>/dev/null || true
  [ -n "${SERVER_PID:-}" ] && wait "$SERVER_PID" 2>/dev/null || true
  [ -n "${TUNNEL_PID:-}" ] && wait "$TUNNEL_PID" 2>/dev/null || true
  rm -f "$TUNNEL_LOG"
}
trap cleanup EXIT INT TERM

echo "Starting Quick Tunnel..."
cloudflared tunnel --url "http://127.0.0.1:$MCP_PORT" --no-autoupdate > "$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!

echo "Waiting for tunnel URL..."
TUNNEL_URL=""
i=0
while [ "$i" -lt 60 ]; do
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
  echo "tunnel URL did not appear; last log lines:" >&2
  tail -20 "$TUNNEL_LOG" >&2
  exit 1
fi

export MCP_PUBLIC_URL="$TUNNEL_URL/mcp"
echo ""
echo "==============================================================="
echo "  Claude.ai connector URL (exact):"
echo "  $MCP_PUBLIC_URL"
echo ""
echo "  Admin login password: $MCP_ADMIN_PASSWORD"
echo "  OAuth credentials: $CREDENTIAL_FILE"
echo "  Show password later: sed -n 's/^MCP_ADMIN_PASSWORD_B64=//p' '$CREDENTIAL_FILE' | openssl base64 -d -A; echo"
echo "  State directory: $MCP_STATE_DIR"
echo ""
echo "  Password and encryption key persist across runs."
echo "  Quick Tunnel URL changes on restart; re-add the connector."
echo "  Press Ctrl+C to stop tunnel and server."
echo "==============================================================="
echo ""

"$ROOT/bin/workspace-mcp" &
SERVER_PID=$!
wait "$SERVER_PID"
