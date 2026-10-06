#!/bin/sh
# Install workspace-mcp in WSL2.
# With systemd enabled (default on Windows 11 / recent Windows 10): installs a
# user service. Without systemd: prints how to run it in the background.
# Usage: ./scripts/install-wsl.sh /path/to/workspace
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE_ROOT="${1:-}"
if [ -z "$WORKSPACE_ROOT" ]; then
  echo "usage: $0 /path/to/workspace" >&2
  exit 1
fi
WORKSPACE_ROOT="$(cd "$WORKSPACE_ROOT" && pwd)"

if grep -qE '(microsoft|WSL)' /proc/version 2>/dev/null; then
  echo "WSL2 detected."
fi

"$ROOT/scripts/bootstrap-go.sh"
GOROOT="$ROOT/.tools/go" PATH="$ROOT/.tools/go/bin:$PATH" \
  "$ROOT/.tools/go/bin/go" build -o "$ROOT/bin/workspace-mcp" ./cmd/workspace-mcp

STATE_DIR="$HOME/.local/share/workspace-mcp"
install -d -m 0700 "$STATE_DIR"
ENV_FILE="$HOME/.config/workspace-mcp.env"
mkdir -p "$(dirname "$ENV_FILE")"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
WORKSPACE_ROOT=$WORKSPACE_ROOT
MCP_HOST=127.0.0.1
MCP_PORT=8787
MCP_MODE=local
# For public mode behind Cloudflare Tunnel, set:
# MCP_MODE=public
# MCP_PUBLIC_URL=https://<your-tunnel-host>/mcp
# MCP_ADMIN_PASSWORD=<long-random-password>
# MCP_STATE_DIR=$STATE_DIR
# MCP_STATE_KEY=<openssl rand -base64 32>
# MCP_TRUST_CLOUDFLARE_TUNNEL=true
EOF
  chmod 0600 "$ENV_FILE"
  echo "Wrote $ENV_FILE - edit before starting."
fi

if systemctl --user status >/dev/null 2>&1 || [ -d /run/user/$(id -u)/systemd ]; then
  mkdir -p ~/.config/systemd/user
  sed -e "s|@ENV_FILE@|$ENV_FILE|g" -e "s|@BIN@|$ROOT/bin/workspace-mcp|g" \
    -e "s|@WORKSPACE_ROOT@|$WORKSPACE_ROOT|g" -e "s|@STATE_DIR@|$STATE_DIR|g" \
    -e '/NoNewPrivileges=/d' -e '/PrivateTmp=/d' -e '/ProtectSystem=/d' -e '/ProtectHome=/d' -e '/ReadWritePaths=/d' \
    "$ROOT/deploy/systemd/workspace-mcp.service" > ~/.config/systemd/user/workspace-mcp.service
  systemctl --user daemon-reload
  echo "systemd (WSL2) available. Start with:"
  echo "  systemctl --user enable --now workspace-mcp"
  echo "  journalctl --user -u workspace-mcp -f"
else
  echo "systemd not enabled in WSL2. Start manually (keep the terminal open or use tmux):"
  echo "  set -a; source $ENV_FILE; set +a; $ROOT/scripts/start.sh"
  echo "Or enable systemd in /etc/wsl.conf ([boot] systemd=true) and run 'wsl --shutdown' in Windows."
fi
