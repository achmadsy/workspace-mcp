# Agentic coding tools — in progress

Checkpoint date: 2026-10-08
Branch: `feature/agentic-coding-tools`
Plan: `IMPLEMENTATION_PLAN.md`

## Goal

Expand `workspace-mcp` from bounded safe tools into opt-in remote coding-agent
capability: mandatory Linux sandbox, isolated outbound network, async commands,
broader workspace operations, typed Git writes/network, isolated credentials,
and OAuth scopes. Safe profile remains default. Agentic mode is RCE-equivalent
and must fail closed.

## Completed

- Existing OAuth/Cloudflare compatibility work remains intact.
- Default-off config gates and bounded execution/job/resource settings.
- Runtime OAuth scopes: `workspace`, `workspace:exec`,
  `workspace:git-write`, `workspace:git-network`; exact scopes persist through
  code/refresh exchange and `TokenInfo` carries `client_id`.
- Hardened sandbox runner:
  - `systemd-run --user --scope`, cgroup properties, and `prlimit`
  - bubblewrap fd-bound workspace, private runtime mounts, clean environment
  - `bwrap --json-status-fd` + `--block-fd` handshake
  - private `slirp4netns` network with host loopback disabled
  - bounded output, timeout/cancel, process-group and helper cleanup
- Owner-bound async jobs with output cursors, capacity, TTL, cancel, and restart loss.
- Workspace operations: stat, ranged read, bounded glob, enhanced search,
  mkdir/delete/move/copy, and prevalidated unified-diff apply.
- Typed Git reads/writes/fetch/pull/push with strict path/ref/refspec/remote
  validation, disabled hooks/helpers/unsafe protocols, and explicit validated
  remote URLs.
- Git credential broker:
  - startup-opened and fd-revalidated owner-only credential files
  - SSH key + pinned known_hosts private mounts
  - anonymous memfd HTTPS askpass + token private mounts
  - credentials unavailable to general execution
  - rejects dangerous repo-local network configuration before credential use
- MCP tool registration:
  - base filesystem/read-Git/capabilities tools
  - capability-gated exec/job, Git-write, and Git-network tools
  - public-mode per-tool scope checks; local mode relies on startup gates
  - accurate read/destructive/open-world annotations
  - metadata-only dangerous-call audit logs
- Launcher `--agentic` flag preserves through tmux re-exec, probes helpers,
  cgroup v2, and user-systemd scope before enabling gates.
- `.env.example`, README, and safe-profile systemd hardening updated.

## Verification completed

- Sequential commands pass with project Go 1.25:

```sh
export GOROOT="$PWD/.tools/go"
export PATH="$GOROOT/bin:$PATH"
go test -cover ./...
CGO_ENABLED=1 go test -race ./...
go vet ./...
sh -n scripts/start-tunnel.sh
git diff --check
go build -o bin/workspace-mcp ./cmd/workspace-mcp
```

- Safe-profile MCP HTTP smoke test completed against disposable workspace:
  all 20 base tools verified over real Streamable HTTP endpoint (`127.0.0.1:8798/mcp`).
- Package statement test coverage:
  - `internal/auth`: 71.1%
  - `internal/config`: 72.7%
  - `internal/git`: 62.5%
  - `internal/httpx`: 80.9%
  - `internal/sandboxexec`: 45.8%
  - `internal/server`: 73.9%
  - `internal/workspace`: 74.0%

## Remaining verification

Current host still lacks `bwrap` and `slirp4netns`, so live agentic startup and
sandbox/network integration have not run here. Do not expose agentic mode until
these pass on a dependency-capable Linux/WSL2 host:

1. Agentic startup self-test with user systemd/cgroup v2.
2. Sandbox visibility/escape tests: host home, OAuth state, credentials, sockets,
   and secret environment invisible; workspace writable.
3. DNS/HTTPS egress through private network; host loopback unreachable.
4. Output/resource/time/cancel/descendant cleanup and async ownership/TTL tests.
5. Typed local Git and disposable bare-remote fetch/pull/push tests.
6. Verify repo hooks cannot run; general exec cannot read credentials; dedicated
   network Git can authenticate.
7. Restart authenticated tunnel with `--agentic`, delete/re-add Claude.ai
   connector for new scopes, run disposable inspect/edit/test/commit/push flow,
   and inspect metadata-only audit logs.

## Important constraints

- `MCP_ENABLE_GIT_NETWORK=true` requires `MCP_ENABLE_GIT_WRITE=true`.
- Quick Tunnel URL changes invalidate OAuth clients/tokens.
- Existing connectors must reconnect after scope changes.
- Project Go must run with `GOROOT=$PWD/.tools/go`; invoking binary without
  matching GOROOT can pair Go 1.25 binary with system Go 1.20 stdlib.
- `deploy/systemd/workspace-mcp.service` is safe-profile only. Agentic runner
  requires a user service/session with usable `systemd-run --user` delegation.
