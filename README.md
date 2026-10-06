# workspace-mcp

A standalone, sandboxed **Workspace MCP server** for Linux and WSL2. It exposes
one configured project directory to remote MCP clients — primarily Claude.ai
custom connectors — over Streamable HTTP, so Claude Web can inspect and modify
a real workspace without VS Code, Claude Desktop, or Claude Code running.

```
Claude Web (claude.ai)
        │  Remote MCP (HTTPS)
        ▼
Cloudflare Tunnel  (cloudflared)
        │
        ▼
127.0.0.1:8787  workspace-mcp   ← this server (single Go binary)
        │
        ├── Files: list / read / write / edit
        ├── Search: bounded literal text search
        └── Git: status / diff (read-only)
```

## What this is NOT

This is a **capability layer, not a coding harness**. It is not Claude Code, not
an agent runtime, not an LLM, and contains no agent loop, planner, subagents,
context manager, or task queue. The MCP client owns all reasoning. There is no
arbitrary shell execution, no process management, and no generic `git` passthrough.

## Tools (exactly seven)

| Tool | Arguments | Behavior |
|---|---|---|
| `workspace_list` | `path?`, `depth?` (default 2, max 8) | Lexical directory entries (`path`, `type`, `size`). Skips `.git`, `node_modules`, `vendor`, `.venv`, `target`, `dist`, `build`; never lists symlinks. |
| `workspace_read` | `path` | Returns `path`, `content`, `size` for one UTF-8 text file (≤1 MiB). Binary files and symlinks are rejected. |
| `workspace_search` | `query`, `path?`, `max_results?` (default 50, max 200) | Literal case-sensitive line search. Returns `relative_path`, `line_number`, `matching_line`, scan counts, and `truncated`. |
| `workspace_write` | `path`, `content` | Atomic create/replace of one UTF-8 file (≤1 MiB), creating parent directories. |
| `workspace_edit` | `path`, `old_text`, `new_text` | Replaces the **exactly one** occurrence of `old_text`; zero or multiple matches fail without mutating. Atomic. |
| `git_status` | — | Runs fixed `git status --short` in the workspace. Returns `stdout`, `stderr`, `exit_code`. |
| `git_diff` | — | Runs fixed `git diff --no-ext-diff --no-textconv`. Same result shape. |

All results are bounded (≤1 MiB git output, 512 KiB listing, 15 s tool deadline).
Every tool result is also serialized as `structuredContent` for clients that
prefer structured data.

## Security model

- **Sandbox**: every path is relative to `WORKSPACE_ROOT`. Requests are executed
  through Linux `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
  RESOLVE_NO_MAGICLINKS` — traversal (`../`), absolute paths, **any symlink
  (including symlinks fully inside the workspace)**, and multiply-linked files
  are refused. The server fails to start on kernels without `openat2`
  (Ubuntu 22.04/24.04 and WSL2 5.15+ are supported).
- **`.git` is reserved** for the filesystem tools; git operations run with a
  scrubbed environment (`GIT_CONFIG_NOSYSTEM=1`, no prompts, no pagers, no
  external diffs) and never accept arguments from the model.
- **Writes are atomic**: same-directory temp file, `fsync`, `rename`, parent
  `fsync`; permissions preserved; temp files cleaned on failure.
- **Auth (public mode)**: embedded OAuth 2.1 — RFC 9728 protected-resource
  metadata, RFC 8414 authorization-server metadata, Dynamic Client Registration
  (public clients only), authorization code + PKCE (S256 only), RFC 8707
  `resource` enforcement, rotating refresh tokens with family revocation on
  replay, opaque SHA-256-hashed tokens. One operator password (Argon2id,
  constant-time, rate-limited) unlocks the consent page.
- **State**: OAuth state is AES-256-GCM encrypted in `MCP_STATE_DIR` (0600
  file, 0700 dir, exclusive flock). Secrets, tokens, passwords, file contents,
  and search queries never appear in logs.
- **What Claude can reach**: only `WORKSPACE_ROOT`. Nothing else — not `/etc`,
  not `~/.ssh`, not other repositories, not the environment, no shell.

## Requirements

- Linux (Ubuntu 22.04/24.04+, Debian 12+) or WSL2, kernel ≥ 5.19 (`openat2`
  resolve flags; 5.15 works on stock Ubuntu/WSL2 kernels)
- Go 1.25 — `./scripts/bootstrap-go.sh` installs it project-locally into
  `.tools/` (verified by SHA-256; no system changes) if your system Go is older
- `git` on PATH for the git tools
- `cloudflared` for remote access from Claude.ai

## Build

```bash
./scripts/bootstrap-go.sh        # fetches Go 1.25 into .tools/ if needed
GO=... .tools/go/bin/go build -o bin/workspace-mcp ./cmd/workspace-mcp
```

## Configuration

Copy `.env.example` and set at minimum:

```text
WORKSPACE_ROOT=/absolute/path/to/project   # the sandbox root
MCP_HOST=127.0.0.1                         # never expose directly
MCP_PORT=8787
MCP_MODE=local                             # or public
```

Public mode additionally requires `MCP_PUBLIC_URL` (the exact HTTPS URL ending
in `/mcp`), `MCP_ADMIN_PASSWORD`, `MCP_STATE_DIR`, and `MCP_STATE_KEY`
(`openssl rand -base64 32`).

## Local development (no auth)

```bash
WORKSPACE_ROOT=/path/to/project ./scripts/start.sh
# then: curl initialize / tools/list / tools/call against http://127.0.0.1:8787/mcp
```

Local mode binds to loopback only and accepts unauthenticated MCP traffic.
Never use local mode behind a tunnel.

## Remote access from Claude.ai

### Option A — Quick Tunnel (testing only)

```bash
MCP_ADMIN_PASSWORD='long-random' \
MCP_STATE_DIR=~/.local/share/workspace-mcp \
MCP_STATE_KEY="$(openssl rand -base64 32)" \
  ./scripts/start-tunnel.sh /path/to/project
```

The script starts `cloudflared`, prints the exact connector URL
(`https://<random>.trycloudflare.com/mcp`), then starts the server. Quick
Tunnels: no account needed, but the URL **changes on every restart**, there is
no SLA, and SSE is unsupported (this server is configured for JSON responses,
so that is fine).

### Option B — Named Tunnel (stable hostname, recommended)

```bash
# Debian/Ubuntu install
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install cloudflared

cloudflared tunnel login
cloudflared tunnel create workspace-mcp
cloudflared tunnel route dns workspace-mcp mcp.example.com
cp deploy/cloudflared/config.yml.example ~/.cloudflared/config.yml  # edit it
cloudflared tunnel run workspace-mcp
```

Then run the server in public mode with
`MCP_PUBLIC_URL=https://mcp.example.com/mcp`. Outbound UDP/TCP 7844 must be
reachable. Optional services: `deploy/systemd/workspace-mcp.service` (expects
`EnvironmentFile` and `@BIN@`/`@WORKSPACE_ROOT@` placeholders — see
`scripts/install-linux.sh`) and `deploy/systemd/cloudflared-workspace-mcp.service`.

### WSL2 specifics

- Run **both** `workspace-mcp` and `cloudflared` inside WSL2; no Windows-native
  components are required.
- With systemd enabled (`[boot] systemd=true` in `/etc/wsl.conf`, then
  `wsl --shutdown` from Windows): `./scripts/install-wsl.sh` installs a user
  service (`systemctl --user enable --now workspace-mcp`).
- Without systemd: start the script in a tmux session or keep a terminal open;
  optionally add the command to `~/.profile` or a Windows Task Scheduler job
  that runs `wsl -e ...` at logon.

### Claude.ai connector setup

1. Start the server + tunnel; note the exact public URL ending in `/mcp`.
2. claude.ai → **Settings → Connectors → Add custom connector**.
3. Paste the **full URL including `/mcp`** (e.g.
   `https://mcp.example.com/mcp`).
4. Claude discovers the OAuth setup automatically (protected-resource metadata
   → DCR). Sign in with your `MCP_ADMIN_PASSWORD` and approve the consent page.
5. The connector shows the seven tools; enable it in a chat and try:
   "list the project files", "read main.go", "search for Greet",
   "write a test file", "edit it", "show git status and diff".

Quick Tunnel users: after each tunnel restart, delete and re-add the connector
with the new URL (the old URL's OAuth state is invalidated by design).

## Tests

```bash
.tools/go/bin/go test ./...       # unit + integration (protocol, OAuth, security)
.tools/go/bin/go test -race ./...
.tools/go/bin/go vet ./...
```

Security cases covered in CI-style tests: path traversal, absolute paths,
outbound/internal/nested symlinks, hard links, `.git` access, binary and
oversized files, atomic-write cleanup, edit occurrence rules, PKCE/redirect/
resource mismatches, code replay, refresh rotation + replay revocation,
CSRF, rate limits, origin validation, panic recovery.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "openat2 ... unavailable" at startup | Kernel lacks `RESOLVE_NO_SYMLINKS`. Use Ubuntu 22.04+/WSL2 5.15+; the server refuses to weaken the policy. |
| Claude: "Couldn't reach the MCP server" | Tunnel down, URL wrong (must end in `/mcp`), or discovery unreachable. Check `cloudflared` log; verify `curl https://<host>/mcp` returns 401 with a `WWW-Authenticate` header. |
| Claude: "Authorization with the MCP server failed" | Wrong password, stale consent, or changed URL. Re-add the connector; each new Quick Tunnel URL resets all tokens. |
| Tool calls fail after tunnel restart | Expected with Quick Tunnels — re-add connector with the new URL. |
| `git_status` says "not a Git repository" | The workspace has no `.git`; run `git init` if intended. |
| 403 "forbidden origin" | A browser sent a mismatched `Origin`; the public origin must equal `MCP_PUBLIC_URL`'s origin. |
| 429 responses | Rate limiting (300 req/min per IP); check for tight client retry loops. |
| WSL2: service not running after Windows restart | Enable systemd in `/etc/wsl.conf` or add the start command to logon automation. |

## What must remain running locally?

Only two processes: **`workspace-mcp`** and **`cloudflared`**.
Claude Code, Claude Desktop, and VS Code are **not required**.

## License

Apache-2.0
