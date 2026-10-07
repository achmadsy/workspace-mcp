# Agentic coding tools — in progress

Checkpoint date: 2026-10-07
Branch: `feature/agentic-coding-tools`
Plan: `/home/achmadsyarifudin/.claude/plans/immutable-sprouting-fairy.md` on original machine (plan also summarized below)

## Goal

Expand `workspace-mcp` from seven bounded tools into opt-in remote coding-agent capability:

- arbitrary commands inside mandatory Linux sandbox
- outbound network access from isolated network namespace
- async command start/status/cancel
- broader safe workspace operations
- typed Git read/write/fetch/pull/push
- isolated Git credentials
- OAuth scopes for dangerous capabilities

Existing safe profile must remain default. Agentic mode is RCE-equivalent and must fail closed.

## User choices

- Arbitrary sandboxed commands, not command allowlist
- Network access enabled
- Git writes including push

## Completed before this checkpoint

OAuth/Cloudflare work is functional and included in this branch:

- Claude.ai-compatible DCR and arbitrary valid HTTPS callbacks
- login/consent Origin handling
- consent callback CSP fix
- Claude Origin allowlist and default-port normalization
- trusted-tunnel bypass for MCP SDK localhost Host protection
- persistent Quick Tunnel OAuth credentials
- tmux-by-default one-command launcher

Agentic groundwork now added:

- `internal/limits/limits.go`: execution/job/fs limits
- `internal/config/config.go`: default-off feature flags, resource settings, helper discovery, credential-file validation
- OAuth server now accepts runtime scope list; validates space-delimited scope sets; metadata advertises runtime scopes; token responses preserve scope; `TokenInfo` splits scopes and carries `client_id`
- `internal/workspace/root_linux.go`: `SandboxFile()` duplicate descriptor for race-safe `ExtraFiles`
- `internal/sandboxexec/runner.go`: initial fail-closed bwrap/systemd-run/prlimit runner, scrubbed environment, bounded output, process-group cleanup, direct argv/script validation

## Important current state

Code compiles and `go test ./...` passes with project Go 1.25.

Sandbox runner is intentionally incomplete and not wired into server:

- isolated outbound network handshake with `slirp4netns` is not implemented
- network-enabled `Run` currently returns `isolated network setup is unavailable`
- no async job manager
- no runner tests
- no Git credential broker
- no new tools registered
- feature flags default false, so current production behavior is unchanged

Do not expose `MCP_ENABLE_EXEC=true` yet.

## Remaining implementation

### 1. Finish sandbox network and job manager

Files: `internal/sandboxexec/runner.go`, new `internal/sandboxexec/jobs.go`, tests.

- Start bwrap with `--unshare-net` and `--json-status-fd`; parse `child-pid`.
- Attach `slirp4netns --configure --mtu=65520 --disable-host-loopback --ready-fd=... --exit-fd=... CHILD_PID tap0` before command executes. Use a synchronization pipe so child waits until slirp reports ready.
- Ensure all helper processes are killed on timeout/cancel.
- Confirm `/proc/self/fd/3` workspace bind survives systemd-run/prlimit/bwrap descriptor chain; add explicit fd-preservation if systemd-run closes it.
- Add async jobs: random IDs, owner binding, bounded output with cursors, concurrency/capacity, TTL, cancel.
- Add sandbox tests: host paths/secrets invisible, workspace writable, network works, output caps, resource limits, descendant kill.

References used during planning:

- bwrap `--json-status-fd` emits newline JSON with `child-pid` and final `exit-code`.
- slirp invocation: `slirp4netns --configure --mtu=65520 --disable-host-loopback --ready-fd=FD --exit-fd=FD PID tap0`.

### 2. Workspace operations

Add fd-relative implementations and tests under `internal/workspace/`:

- `Stat`
- `ReadRange`
- `Glob`
- enhanced Search options
- `Mkdir`
- capped `Delete`
- `Move`
- `Copy`
- pure-Go validated unified-diff `ApplyPatch`

Reuse `ValidatePath`, `openat2`, `openParent`, `atomicWrite`, `writeMu`; never follow symlinks or expose `.git`.

### 3. Typed Git service

Refactor `internal/git/service.go` while preserving `Status`/`Diff`:

- read: log/show/branches/remotes
- write: add/restore/commit/branch/switch/stash
- network: fetch/pull/push
- strict ref/path/remote validation; no generic Git passthrough
- run through sandbox runner

### 4. Credential broker

- Modes: none/ssh_key/https_token
- Credentials outside workspace, owner-only, single-link
- Never mount into general exec
- SSH: private key + pinned known_hosts, no agent forwarding
- HTTPS: ephemeral askpass
- Resolve and validate remote URL server-side; prevent repo config redirecting credential-bearing calls

### 5. Register and scope MCP tools

Update `internal/server/server.go` and split `internal/server/tools.go`:

- existing seven names/schema compatible
- new fs, exec, job, Git, and capability tools
- scopes: `workspace`, `workspace:exec`, `workspace:git-write`, `workspace:git-network`
- public-mode handlers inspect `CallToolRequest.Extra.TokenInfo`; local mode uses runtime flags
- accurate annotations: exec/Git network `OpenWorldHint=true`
- metadata-only audit logging

Important: current `server.New` still calls old `auth.NewServer(...)` variadically with no dangerous scopes, so metadata remains base `workspace` only until wiring is done.

### 6. Launcher/docs/deploy

- Add `scripts/start-tunnel.sh --agentic`; preserve flag when re-execing into tmux.
- Check/install guidance for bwrap, slirp4netns, user systemd/cgroup v2.
- Document credentials and RCE/exfiltration warning.
- Reconcile systemd hardening with user namespaces/bwrap.

### 7. Verification

Sequential:

```sh
export GOROOT="$PWD/.tools/go"
export PATH="$GOROOT/bin:$PATH"
gofmt -w <changed-go-files>
go test ./...
CGO_ENABLED=1 go test -race ./...
go vet ./...
sh -n scripts/start-tunnel.sh
git diff --check
go build -o bin/workspace-mcp ./cmd/workspace-mcp
```

Then safe-profile and agentic-profile MCP smoke tests, followed by disposable Claude.ai workflow and disposable remote push.

## Environment note

Current machine had none of these installed when checked:

- `bwrap`
- `slirp4netns`

Agentic startup should therefore fail closed until dependencies are installed. Safe profile remains usable.

## Last verified result

```text
go test ./...  # PASS, 2026-10-07
```

Use project-local Go with `GOROOT=$PWD/.tools/go`; invoking `.tools/go/bin/go` without exporting `GOROOT` can accidentally pair Go 1.25 binary with system Go 1.20 stdlib.
