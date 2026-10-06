#!/bin/sh
# Install workspace-mcp plus optional systemd services on Linux.
# Usage: sudo ./scripts/install-linux.sh /path/to/workspace
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE_ROOT="${1:-}"
if [ -z "$WORKSPACE_ROOT" ]; then
  echo "usage: $0 /path/to/workspace" >&2
  exit 1
fi
WORKSPACE_ROOT="$(cd "$WORKSPACE_ROOT" && pwd)"

# Build the binary with the project-local toolchain.
"$ROOT/scripts/bootstrap-go.sh"
GOROOT="$ROOT/.tools/go" PATH="$ROOT/.tools/go/bin:$PATH" \
  "$ROOT/.tools/go/bin/go" build -o "$ROOT/bin/workspace-mcp" ./cmd/workspace-mcp

install -m 0755 "$ROOT/bin/workspace-mcp" /usr/local/bin/workspace-mcp

if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  STATE_DIR="/var/lib/workspace-mcp"
  install -d -m 0700 "$STATE_DIR"
  ENV_FILE="/etc/workspace-mcp.env"
  if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<EOF
WORKSPACE_ROOT=$WORKSPACE_ROOT
MCP_HOST=127.0.0.1
MCP_PORT=8787
MCP_MODE=local
# For public mode behind Cloudflare Tunnel, set:
# MCP_MODE=public
# MCP_PUBLIC_URL=https://mcp.example.com/mcp
# MCP_ADMIN_PASSWORD=<long-random-password>
# MCP_STATE_DIR=$STATE_DIR
# MCP_STATE_KEY=<openssl rand -base64 32>
# MCP_TRUST_CLOUDFLARE_TUNNEL=true
EOF
    chmod 0600 "$ENV_FILE"
    echo "Wrote $ENV_FILE - edit before enabling the service."
  fi
  sed -e "s|@ENV_FILE@|$ENV_FILE|g" -e "s|@BIN@|/usr/local/bin/workspace-mcp|g" \
    -e "s|@WORKSPACE_ROOT@|$WORKSPACE_ROOT|g" -e "s|@STATE_DIR@|$STATE_DIR|g" \
    "$ROOT/deploy/systemd/workspace-mcp.service" > /etc/systemd/system/workspace-mcp.service
  systemctl daemon-reload
  echo "Optional: systemctl enable --now workspace-mcp"
else
  echo "systemd not detected or not root; run ./scripts/start.sh $WORKSPACE_ROOT directly."
fi
echo "Done. Binary: /usr/local/bin/workspace-mcp"
