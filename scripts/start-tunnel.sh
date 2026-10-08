#!/bin/sh
# Start a Cloudflare Quick Tunnel and workspace-mcp with secure persistent OAuth
# credentials. Usage: ./scripts/start-tunnel.sh [--fg] [--agentic] /path/to/workspace
#
# Default: the launcher re-executes itself inside a dedicated detached tmux
# server and session (name: workspace-mcp-tunnel), then returns immediately.
# Use --fg to run in the calling terminal instead (Ctrl+C stops both processes).
set -e
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FOREGROUND=false
AGENTIC=false
WORKSPACE_ROOT=""
SESSION_NAME="${WORKSPACE_MCP_SESSION:-workspace-mcp-tunnel}"
TMUX_SOCKET_NAME="${WORKSPACE_MCP_TMUX_SOCKET:-workspace-mcp}"
for arg in "$@"; do
  case "$arg" in
    --fg|--foreground) FOREGROUND=true ;;
    --agentic) AGENTIC=true ;;
    --*) echo "unknown option: $arg" >&2; exit 1 ;;
    *) if [ -z "$WORKSPACE_ROOT" ]; then WORKSPACE_ROOT="$arg"; else echo "unexpected argument: $arg" >&2; exit 1; fi ;;
  esac
done
if [ -z "$WORKSPACE_ROOT" ]; then
  WORKSPACE_ROOT="${WORKSPACE_ROOT:-}"
fi
if [ -z "$WORKSPACE_ROOT" ]; then
  echo "usage: $0 [--fg] [--agentic] /path/to/workspace" >&2
  exit 1
fi
if [ ! -d "$WORKSPACE_ROOT" ]; then
  echo "workspace does not exist or is not a directory: $WORKSPACE_ROOT" >&2
  exit 1
fi
WORKSPACE_ROOT="$(cd "$WORKSPACE_ROOT" && pwd)"
export WORKSPACE_ROOT

QUICK_MISSING=""
BASE_PACKAGES=""
for command_name in cloudflared openssl curl python3 sha256sum tar git; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    QUICK_MISSING="${QUICK_MISSING}${QUICK_MISSING:+ }$command_name"
    case "$command_name" in
      openssl|curl|python3|tar|git) BASE_PACKAGES="${BASE_PACKAGES}${BASE_PACKAGES:+ }$command_name" ;;
      sha256sum) BASE_PACKAGES="${BASE_PACKAGES}${BASE_PACKAGES:+ }coreutils" ;;
    esac
  fi
done

AGENTIC_MISSING=""
AGENTIC_PACKAGES=""
if [ "$AGENTIC" = true ]; then
  for command_name in bwrap slirp4netns systemd-run prlimit; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      AGENTIC_MISSING="${AGENTIC_MISSING}${AGENTIC_MISSING:+ }$command_name"
      case "$command_name" in
        bwrap) AGENTIC_PACKAGES="${AGENTIC_PACKAGES}${AGENTIC_PACKAGES:+ }bubblewrap" ;;
        slirp4netns) AGENTIC_PACKAGES="${AGENTIC_PACKAGES}${AGENTIC_PACKAGES:+ }slirp4netns" ;;
        systemd-run) AGENTIC_PACKAGES="${AGENTIC_PACKAGES}${AGENTIC_PACKAGES:+ }systemd" ;;
        prlimit) AGENTIC_PACKAGES="${AGENTIC_PACKAGES}${AGENTIC_PACKAGES:+ }util-linux" ;;
      esac
    fi
  done
fi

if [ -n "$QUICK_MISSING" ] || [ -n "$AGENTIC_MISSING" ]; then
  echo "Missing startup dependencies:" >&2
  [ -n "$QUICK_MISSING" ] && echo "  Quick Tunnel: $QUICK_MISSING" >&2
  [ -n "$AGENTIC_MISSING" ] && echo "  Agentic mode: $AGENTIC_MISSING" >&2
  echo "" >&2

  OS_ID=""
  OS_ID_LIKE=""
  if [ -r /etc/os-release ]; then
    OS_ID="$(. /etc/os-release && printf '%s' "${ID:-}")"
    OS_ID_LIKE="$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")"
  fi
  case " $OS_ID $OS_ID_LIKE " in
    *" debian "*|*" ubuntu "*) ;;
    *)
      echo "Automatic installation supports Debian, Ubuntu, and WSL2 only." >&2
      exit 1
      ;;
  esac
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Automatic installation requires apt-get." >&2
    exit 1
  fi
  if [ ! -t 0 ]; then
    echo "Run this command in an interactive terminal to approve installation." >&2
    exit 1
  fi

  printf "Install missing dependencies now? [y/N] " >&2
  answer=""
  read -r answer || answer=""
  case "$answer" in
    [yY]|[yY][eE][sS]) ;;
    *) exit 1 ;;
  esac

  run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
      "$@"
    else
      sudo "$@"
    fi
  }

  if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
      echo "sudo is required to install system packages." >&2
      exit 1
    fi
    run_privileged true
  fi

  PACKAGES="$BASE_PACKAGES"
  if [ -n "$AGENTIC_PACKAGES" ]; then
    PACKAGES="${PACKAGES}${PACKAGES:+ }$AGENTIC_PACKAGES"
  fi
  if [ -n "$PACKAGES" ]; then
    run_privileged env DEBIAN_FRONTEND=noninteractive apt-get update
    # Package names are assembled from the fixed command mappings above.
    # shellcheck disable=SC2086
    run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y $PACKAGES
  fi

  if ! command -v cloudflared >/dev/null 2>&1; then
    run_privileged mkdir -p --mode=0755 /usr/share/keyrings
    CLOUDFLARE_KEY="$(mktemp)"
    if ! curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o "$CLOUDFLARE_KEY"; then
      rm -f "$CLOUDFLARE_KEY"
      echo "Failed to download the Cloudflare package signing key." >&2
      exit 1
    fi
    if ! run_privileged tee /usr/share/keyrings/cloudflare-main.gpg < "$CLOUDFLARE_KEY" >/dev/null; then
      rm -f "$CLOUDFLARE_KEY"
      exit 1
    fi
    rm -f "$CLOUDFLARE_KEY"
    printf '%s\n' "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" |
      run_privileged tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
    run_privileged env DEBIAN_FRONTEND=noninteractive apt-get update
    run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y cloudflared
  fi

  STILL_MISSING=""
  for command_name in cloudflared openssl curl python3 sha256sum tar git; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      STILL_MISSING="${STILL_MISSING}${STILL_MISSING:+ }$command_name"
    fi
  done
  if [ "$AGENTIC" = true ]; then
    for command_name in bwrap slirp4netns systemd-run prlimit; do
      if ! command -v "$command_name" >/dev/null 2>&1; then
        STILL_MISSING="${STILL_MISSING}${STILL_MISSING:+ }$command_name"
      fi
    done
  fi
  if [ -n "$STILL_MISSING" ]; then
    echo "Dependencies remain unavailable after installation: $STILL_MISSING" >&2
    exit 1
  fi
fi

if [ "$AGENTIC" = true ]; then
  _uid="$(id -u)"
  if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -n "$_uid" ] && [ -d "/run/user/$_uid" ]; then
    XDG_RUNTIME_DIR="/run/user/$_uid"
    export XDG_RUNTIME_DIR
  fi
  unset _uid

  _has_cgroup_v2=false
  if [ -f /sys/fs/cgroup/cgroup.controllers ] || [ -f /sys/fs/cgroup/unified/cgroup.controllers ]; then
    _has_cgroup_v2=true
  fi
  _init_comm=""
  if command -v ps >/dev/null 2>&1; then
    _init_comm="$(ps -p 1 -o comm= 2>/dev/null | tr -d '[:space:]' || true)"
  fi

  if [ "$_has_cgroup_v2" != true ]; then
    if [ "$_init_comm" = "systemd" ]; then
      echo "--agentic requires cgroup v2, but it is not mounted on this system (PID 1 is already systemd)." >&2
      echo "This host uses legacy cgroup v1 or lacks unified cgroups. No change to /etc/wsl.conf is needed." >&2
    else
      echo "--agentic requires cgroup v2. On WSL2, enable systemd in /etc/wsl.conf ([boot] systemd=true), run 'wsl --shutdown' from Windows, then retry." >&2
    fi
    echo "Tip: Safe profile without --agentic is fully functional and requires no cgroup configuration." >&2
    unset _has_cgroup_v2 _init_comm
    exit 1
  fi

  if ! systemd-run --user --scope --quiet --collect -- /bin/true >/dev/null 2>&1; then
    if [ "$_init_comm" = "systemd" ]; then
      echo "--agentic requires a working user systemd manager (systemd-run --user failed; XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-unset})." >&2
      echo "Try running from a login shell; no change to /etc/wsl.conf is needed since systemd is already active." >&2
    else
      echo "--agentic requires a usable user systemd manager and delegated cgroup scope. On WSL2, enable systemd in /etc/wsl.conf, run 'wsl --shutdown' from Windows, then retry." >&2
    fi
    echo "Tip: Safe profile without --agentic is fully functional and requires no cgroup configuration." >&2
    unset _has_cgroup_v2 _init_comm
    exit 1
  fi
  unset _has_cgroup_v2 _init_comm
  export MCP_ENABLE_EXEC=true
  export MCP_ENABLE_GIT_WRITE=true
  export MCP_ENABLE_GIT_NETWORK=true
fi

if [ "$FOREGROUND" != true ] && [ -z "${TMUX:-}" ]; then
  if command -v tmux >/dev/null 2>&1; then
    if tmux -L "$TMUX_SOCKET_NAME" has-session -t "$SESSION_NAME" 2>/dev/null; then
      echo "workspace-mcp is already running in tmux session '$SESSION_NAME'."
      BOX="$(tmux -L "$TMUX_SOCKET_NAME" capture-pane -pt "$SESSION_NAME" 2>/dev/null | sed -n '/===/,/===/p' || true)"
      if [ -n "$BOX" ]; then
        printf '\n%s\n\n' "$BOX"
      fi
      echo "Attach:  tmux -L $TMUX_SOCKET_NAME attach -t $SESSION_NAME"
      echo "Stop:    tmux -L $TMUX_SOCKET_NAME kill-server"
      exit 0
    fi
    AGENTIC_ARG=""
    [ "$AGENTIC" = true ] && AGENTIC_ARG=" --agentic"
    tmux -L "$TMUX_SOCKET_NAME" new-session -d -s "$SESSION_NAME" \
      "exec '$0' --fg$AGENTIC_ARG '$WORKSPACE_ROOT'"
    echo "Starting Quick Tunnel in background (tmux session '$SESSION_NAME')..."
    echo "Waiting for connector URL and credentials..."
    i=0
    BOX=""
    while [ "$i" -lt 60 ]; do
      if ! tmux -L "$TMUX_SOCKET_NAME" has-session -t "$SESSION_NAME" 2>/dev/null; then
        echo "Server failed to start; session exited." >&2
        exit 1
      fi
      PANE="$(tmux -L "$TMUX_SOCKET_NAME" capture-pane -pt "$SESSION_NAME" 2>/dev/null || true)"
      if echo "$PANE" | grep -q "Claude.ai connector URL"; then
        BOX="$(echo "$PANE" | sed -n '/===/,/===/p')"
        [ -n "$BOX" ] && break
      fi
      i=$((i + 1))
      sleep 1
    done
    if [ -n "$BOX" ]; then
      printf '\n%s\n\n' "$BOX"
    else
      echo "Tunnel started, but could not capture URL yet."
    fi
    echo "Started in tmux session '$SESSION_NAME' (stays running when you log out of this shell)."
    echo "Attach:  tmux -L $TMUX_SOCKET_NAME attach -t $SESSION_NAME"
    echo "Stop:    tmux -L $TMUX_SOCKET_NAME kill-server"
    exit 0
  fi
  echo "tmux not found; running in foreground instead (Ctrl+C stops everything)." >&2
fi

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
if [ "$AGENTIC" = true ]; then
  echo "  Agentic profile: ENABLED (sandboxed RCE, network, Git writes/push)"
fi
echo ""
echo "  Password and encryption key persist across runs."
echo "  Quick Tunnel URL changes on restart; re-add the connector."
echo "  Press Ctrl+C to stop tunnel and server."
echo "==============================================================="
echo ""

"$ROOT/bin/workspace-mcp" &
SERVER_PID=$!
wait "$SERVER_PID"
