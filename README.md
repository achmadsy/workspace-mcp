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
        ├── Files: bounded read, search, glob, patch, copy/move/delete
        ├── Commands: optional sandboxed short + async execution
        └── Git: typed read/write/fetch/pull/push operations
```

## What this is NOT

This is a **capability layer, not a coding harness**. It is not Claude Code, not
an LLM, and contains no agent loop, planner, subagents, or context manager. MCP
client owns reasoning. Server provides bounded typed operations plus optional
sandbox execution; it never exposes a generic host shell or generic Git passthrough.

## Tools

Safe profile is default. It exposes:

- Workspace: `workspace_list`, `workspace_read`, `workspace_stat`,
  `workspace_read_range`, `workspace_glob`, `workspace_search`,
  `workspace_write`, `workspace_edit`, `workspace_mkdir`, `workspace_delete`,
  `workspace_move`, `workspace_copy`, `workspace_apply_patch`.
- Git reads: `git_status`, `git_diff`, `git_log`, `git_show`, `git_branches`,
  `git_remotes`.
- Introspection: `server_capabilities`.

Agentic gates add:

| Gate / OAuth scope | Tools |
|---|---|
| `MCP_ENABLE_EXEC` / `workspace:exec` | `exec_run`, `exec_start`, `exec_status`, `exec_cancel` |
| `MCP_ENABLE_GIT_WRITE` / `workspace:git-write` | `git_add`, `git_restore`, `git_commit`, `git_branch`, `git_switch`, `git_stash_push`, `git_stash_pop` |
| `MCP_ENABLE_GIT_NETWORK` / `workspace:git-network` | `git_fetch`, `git_pull`, `git_push` |

Tool names are stable, but a few response shapes have grown. `workspace_glob`
returns `{paths, truncated}` plus `truncated_reason` when the list is cut short,
and returns the sorted partial list instead of an error when a scan or result
limit is hit. `workspace_search`
adds `truncated_reason`, `skipped_dirs`, and an `include_ignored` option.
Results are bounded and serialized as `structuredContent`; operation failures
remain visible MCP tool errors rather than transport failures.

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
- **Audit**: exec, Git write/network, and every mutating workspace tool
  (`workspace_write`, `workspace_edit`, `workspace_mkdir`, `workspace_delete`,
  `workspace_move`, `workspace_copy`, `workspace_apply_patch`) log one entry per
  call with the client ID, tool, request ID, paths, byte counts, and an error
  flag. Content, edit text, and patch text are never logged.
- **Safe profile reach**: only `WORKSPACE_ROOT`. Nothing else — not `/etc`,
  not `~/.ssh`, not other repositories, not host environment, no host shell.
- **Agentic execution**: every command runs through `systemd-run --user --scope`,
  `prlimit`, and `bubblewrap`; no unsandboxed fallback. Workspace is fd-bound at
  `/workspace`; runtime trees are read-only; home/tmp/proc/dev are private;
  environment starts clean; output, time, memory, CPU, PIDs, open files, jobs,
  and retention are bounded. Network uses a private namespace attached through
  `slirp4netns` with host loopback blocked.
- **Credential isolation**: general execution never receives Git credentials.
  Dedicated network Git commands receive only pre-opened SSH key + pinned
  `known_hosts`, or an anonymous askpass helper + HTTPS token. Repo-local URL
  rewrites, proxy/TLS overrides, credential helpers, SSH overrides, hooks,
  external filters, and unsafe transports are rejected or disabled.

> **Warning:** agentic mode is remote-code-execution-equivalent by design. Code
> inside the workspace can read and exfiltrate all workspace content through
> outbound network. Enable it only for an owner-controlled connector and only
> for workspaces whose contents may be exposed to that connector.

### Sandbox network reach

When `MCP_ENABLE_EXEC` is on, sandboxed commands get a private network
namespace attached through `slirp4netns`, with DNS served by slirp at
`10.0.2.3`. `--disable-host-loopback` blocks only the **host's own loopback**
(`127.0.0.0/8` on the machine running the server), so services bound to
`127.0.0.1` here, such as the MCP server itself or a local database, are not
reachable from the sandbox.

It is **not** an egress filter. Sandboxed code can still open outbound
connections to anything the host can route to, including:

- other machines on your LAN and any RFC 1918 range (`10/8`, `172.16/12`,
  `192.168/16`), such as routers, NAS devices, and internal dashboards;
- link-local addresses, notably the cloud metadata endpoint
  `169.254.169.254` when the server runs on a cloud VM;
- the public internet.

Treat the sandbox as having the same network position as the host's user for
outbound traffic. If that matters for your environment, enforce limits outside
the server: run it on a host or VLAN with restricted egress, or add
host-firewall rules for the server user (for example `nftables` rules matching
the user's UID or the `slirp4netns` helper), and block `169.254.169.254` on
cloud VMs. A built-in egress policy is not implemented yet.

`server_capabilities` reports `exec_network: true` whenever exec is enabled so
a client can tell.

## Requirements

- Linux (Ubuntu 22.04/24.04+, Debian 12+) or WSL2, kernel ≥ 5.19 (`openat2`
  resolve flags; 5.15 works on stock Ubuntu/WSL2 kernels)
- Go 1.25 — `./scripts/bootstrap-go.sh` installs it project-locally into
  `.tools/` (verified by SHA-256; no system changes) if your system Go is older
- `git` on PATH for Git tools
- `cloudflared` for remote access from Claude.ai
- Agentic mode only: `bubblewrap`, `slirp4netns`, `prlimit`, cgroup v2, and a
  usable user systemd manager (`systemd-run --user --scope -- /bin/true`)

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
(`openssl rand -base64 32`). See `.env.example` for every agentic resource and
credential setting.

### Agentic profile

Quick Tunnel launcher can explicitly enable all agentic gates:

```bash
./scripts/start-tunnel.sh --agentic /path/to/project
```

Launcher fails before startup unless sandbox helpers, cgroup v2, and user
systemd scope work. Existing invocations without `--agentic` remain safe.

For manual startup, set only capabilities needed:

```text
MCP_ENABLE_EXEC=true
MCP_ENABLE_GIT_WRITE=true
MCP_ENABLE_GIT_NETWORK=true   # requires Git write
```

Git credentials are optional (`MCP_GIT_CREDENTIAL_MODE=none`). For pushes:

```text
# SSH
MCP_GIT_CREDENTIAL_MODE=ssh_key
MCP_GIT_CREDENTIAL_FILE=/secure/outside/workspace/id_ed25519
MCP_GIT_KNOWN_HOSTS_FILE=/secure/outside/workspace/known_hosts

# or HTTPS token
MCP_GIT_CREDENTIAL_MODE=https_token
MCP_GIT_CREDENTIAL_FILE=/secure/outside/workspace/token

MCP_GIT_ALLOWED_REMOTES=origin
```

Credential files must be regular, single-linked, server-owned, mode `0600` or
stricter, and outside workspace. Tokens contain exactly one non-empty UTF-8
line. SSH mode requires pinned `known_hosts`; SSH agent forwarding is never used.

Adding scopes changes OAuth consent. Delete and re-add existing Claude.ai
connector after enabling agentic gates. Async jobs live in memory, expire after
configured TTL, and disappear on server restart.

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
./scripts/start-tunnel.sh /path/to/project
```

By default the launcher runs inside a dedicated detached tmux server and a
session named `workspace-mcp-tunnel`, then returns immediately:

```bash
tmux -L workspace-mcp attach -t workspace-mcp-tunnel   # watch logs / interact
tmux -L workspace-mcp kill-server   # stop tunnel and server
```

The dedicated tmux server preserves the launcher's current login environment
and avoids inheriting confinement from an existing tmux server. Add `--fg` to
run in the calling terminal instead (Ctrl+C stops both processes). Set a custom
session name with `WORKSPACE_MCP_SESSION` or socket name with
`WORKSPACE_MCP_TMUX_SOCKET`.

This one command checks startup dependencies first and prints install guidance
for anything missing, including `cloudflared` and all `--agentic` helpers. It
then bootstraps Go if needed, builds the server, generates or reuses secure OAuth
credentials, starts `cloudflared`, prints the exact connector URL
(`https://<random>.trycloudflare.com/mcp`) and the admin login password, then
starts the server.

Credentials and encrypted OAuth state live under
`${XDG_DATA_HOME:-$HOME/.local/share}/workspace-mcp`: the directory is mode
0700 and `quick-tunnel.env` is mode 0600. Every startup prints the connector
URL and admin login password so they can be copied directly into Claude.ai.
The launcher also prints a command for retrieving the password later.
Environment values `MCP_ADMIN_PASSWORD`,
`MCP_STATE_KEY`, and `MCP_STATE_DIR` override these defaults.

Quick Tunnels need no Cloudflare account, but have no SLA and the URL
**changes on every restart**. Delete and re-add the Claude.ai connector after
each restart; OAuth clients and tokens reset when the public URL changes, while
the admin password and encryption key remain stable. SSE is unsupported, so
the server uses JSON responses.

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
5. Connector shows safe-profile tools plus any enabled agentic tools; enable it
   in a chat and try: "list project files", "read main.go", "search for Greet",
   "write a test file", "edit it", "show git status and diff".

Quick Tunnel users: after each tunnel restart, delete and re-add the connector
with the new URL (the old URL's OAuth state is invalidated by design).

## Tests

```bash
.tools/go/bin/go test ./...       # unit + integration (protocol, OAuth, security)
.tools/go/bin/go test -race ./...
.tools/go/bin/go vet ./...
```

Security cases covered in CI-style tests: traversal/absolute paths, symlinks,
hard links, `.git`, binary/oversized files, atomic writes, capped recursive
operations, patch prevalidation, Git option/ref/remote validation, credential
owner/mode/link checks and path replacement, async ownership/cursors/capacity,
PKCE/redirect/resource mismatches, code replay, refresh replay revocation,
OAuth scopes, CSRF, rate limits, origin validation, and panic recovery.

Live sandbox/network integration tests require agentic dependencies. If absent,
configuration fails closed before agentic startup; safe-profile tests still run.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "openat2 ... unavailable" at startup | Kernel lacks `RESOLVE_NO_SYMLINKS`. Use Ubuntu 22.04+/WSL2 5.15+; the server refuses to weaken the policy. |
| Claude: "Couldn't reach the MCP server" | Tunnel down, URL wrong (must end in `/mcp`), or discovery unreachable. Check `cloudflared` log; verify `curl https://<host>/mcp` returns 401 with a `WWW-Authenticate` header. |
| Claude: "Authorization with the MCP server failed" | Wrong password, stale consent, or changed URL. Re-add the connector; each new Quick Tunnel URL resets all tokens. |
| Tool calls fail after tunnel restart | Expected with Quick Tunnels — re-add connector with the new URL. |
| `git_status` says "not a Git repository" | The workspace has no `.git`; run `git init` if intended. |
| 403 "forbidden origin" on `/mcp` | A browser sent a mismatched `Origin`; the public origin must equal `MCP_PUBLIC_URL`'s origin. OAuth login and consent use CSRF tokens and are not subject to this MCP endpoint check. |
| Login or consent form fails | Password, expired browser session, or CSRF validation failed. Restart the authorization flow from the connector. |
| 429 responses | Rate limiting (300 req/min per IP); check for tight client retry loops. |
| WSL2: service not running after Windows restart | Enable systemd in `/etc/wsl.conf` or add the start command to logon automation. |
| Agentic startup says helper unavailable | Install `bubblewrap`, `slirp4netns`, and `util-linux` (`prlimit`), then verify user namespaces and `systemd-run --user --scope -- /bin/true`. |
| Agentic startup says cgroup unavailable | Require cgroup v2 and user-systemd delegation. On WSL2 enable systemd, run `wsl --shutdown`, then retry from a fresh distro session. |
| Git credential rejected | Credential must be outside workspace, regular, single-linked, owned by server UID, and mode `0600` or stricter. |

## What must remain running locally?

Only two processes: **`workspace-mcp`** and **`cloudflared`**.
Claude Code, Claude Desktop, and VS Code are **not required**.

## License

Apache-2.0
