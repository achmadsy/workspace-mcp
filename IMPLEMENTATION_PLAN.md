# Agentic coding tools implementation plan

## Context

`workspace-mcp` currently exposes seven bounded file/Git tools. That is enough for inspection and small edits, but not for an autonomous coding workflow: agents cannot create/remove/move files, apply patches, run builds/tests, manage long-running commands, or perform normal Git write/network operations.

Requested profile is intentionally powerful: arbitrary sandboxed commands, outbound network access, and Git push. Treat it as remote code execution by design. Preserve existing safe profile by default; expose agentic capabilities only through explicit runtime flags and OAuth scopes. Never run arbitrary commands directly as server user: command startup must fail closed unless tested Linux sandbox and resource controls are available. Preserve current OAuth, tunnel, origin, CSP, launcher, and test changes.

## Implementation

### 1. Add explicit agentic capability profile

Update `internal/config/config.go`, `internal/limits/limits.go`, `.env.example`, and launcher/deployment docs.

- Add default-off gates: `MCP_ENABLE_EXEC`, `MCP_ENABLE_GIT_WRITE`, and `MCP_ENABLE_GIT_NETWORK`. Keep existing seven tools available without these flags.
- Add bounded settings for synchronous timeout, maximum async jobs, job TTL, stdout/stderr limits, memory, CPU, process count, open files, and allowed read-only runtime mounts. Reject unsafe or internally inconsistent values at startup.
- Require `bwrap` for execution and command-backed Git writes. For outbound network, also require `slirp4netns`; create private network namespace with outbound NAT instead of sharing host network namespace. Probe helpers at startup and run harmless sandbox self-test. No unsandboxed fallback.
- Require usable CPU/memory/PID controls. Prefer cgroup v2 through usable user `systemd-run` scope; retain `prlimit` as second layer. Refuse agentic mode when mandatory isolation/limits cannot be established.
- Add launcher `--agentic` option enabling all three gates after dependency checks; do not silently enable remote RCE for existing users.

### 2. Build hardened sandbox runner and async job manager

Create `internal/sandboxexec/` and reuse from command and Git services.

- Support either direct `argv: []string` or mutually exclusive `script: string`. Scripts run through fixed `/bin/sh -c` inside sandbox; no shell parses direct argv. Validate count/length, UTF-8, NULs, cwd, environment keys, and total input size.
- Bind already-open workspace root through `/proc/self/fd/...` read/write at `/workspace`. Use `workspace.ValidatePath` plus existing `openat2` rules for cwd validation. Never expose host home, OAuth state, tunnel credentials, SSH agent sockets, Docker sockets, or unrelated host paths.
- Mount only required runtime trees read-only (`/usr`, `/bin`, required libraries, configured toolchain roots), synthetic/minimal `/etc`, CA certificates, private tmpfs `/tmp` and `$HOME`, isolated `/proc` and `/dev`. Create new mount, PID, IPC, UTS, cgroup, session, and network namespaces; use `--die-with-parent`.
- Build environment from scratch. Keep small safe baseline and allow caller overrides only for validated non-secret keys. Reject `LD_*`, shell startup variables, `GIT_*`, `SSH_*`, cloud credentials, token/key/password-shaped names, and server configuration secrets.
- Enforce cgroup and rlimit bounds, small execution semaphore, bounded stdout/stderr, wall timeout, cancellation, process-group termination, and descendant cleanup. Return exit code, signal, duration, timeout/cancel state, and separate truncation flags.
- Add in-memory job manager for commands exceeding HTTP timeout constraints. Jobs use random IDs, belong to authenticated client/token identity, retain bounded output, have fixed concurrency/capacity, TTL eviction, and disappear on restart.
- Expose `exec_run` for short commands and `exec_start`, `exec_status`, `exec_cancel` for long jobs. `exec_status` accepts stdout/stderr cursors. General execution receives network egress but never Git credentials.

### 3. Expand workspace operations without weakening path confinement

Add implementations under `internal/workspace/`, reusing `ValidatePath`, `Root.open`, `openParent`, `atomicWrite`, `writeMu`, hard-link checks, and fd-relative syscalls.

- `workspace_stat`: type, size, mode, modification time without following symlinks.
- `workspace_read_range`: bounded byte range plus total size and next offset; preserve UTF-8/binary policy.
- `workspace_glob`: deterministic bounded matching below optional path, without symlink traversal or `.git` access.
- Extend `workspace_search` compatibly with optional case-insensitive matching, include globs, and context lines while retaining literal defaults and scan limits.
- `workspace_mkdir`, `workspace_delete`, `workspace_move`, `workspace_copy`. Refuse workspace root and `.git`; use fd-relative operations; cap recursive deletion; copy regular single-linked files only; state overwrite behavior explicitly.
- `workspace_apply_patch`: parse unified diffs in Go, validate every path/hunk before mutation, reject absolute/traversal/`.git`/symlink targets, and commit each file using atomic-write machinery. Never invoke host `patch`.

Keep existing names/schemas backward compatible. Mark reads explicitly read-only/non-destructive/idempotent, mutations destructive with accurate idempotency, all filesystem tools `OpenWorldHint=false`.

### 4. Expand Git through typed operations, not generic passthrough

Refactor `internal/git/service.go` to use sandbox runner while preserving current `git_status` and `git_diff` behavior and output shape.

- Read: `git_log`, `git_show`, branch and remote inspection.
- Local writes: `git_add`, `git_restore`, `git_commit`, `git_branch`, `git_switch`, `git_stash`. Validate paths and refs; reject option injection.
- Network: `git_fetch`, `git_pull`, `git_push`. Accept only configured remote names and server-validated HTTPS/SSH URLs/refspecs. Disable prompts, aliases, pagers, external diffs, unapproved remote helpers, and hooks during credential-bearing operations.
- Keep command execution as escape hatch for unusual local Git workflows; dedicated Git tools provide predictable schemas, annotations, bounds, audit data, and credential isolation.

### 5. Isolate Git network credentials

Add credential config/loading to `internal/config/` and broker to `internal/git/`.

- Support `none`, `ssh_key`, `https_token`. Credential and known-host files must be absolute, outside workspace, regular single-linked, owned by server user, mode `0600` or stricter. Never log contents.
- Never mount credentials into `exec_*` or local Git. SSH operations bind key and pinned `known_hosts` read-only at private paths; force `IdentitiesOnly=yes`, `StrictHostKeyChecking=yes`; never forward agent.
- HTTPS operations create ephemeral sandbox-private askpass helper and provide token only to fixed Git child. Disable repo/global credential helpers and clear secret after completion.
- Override dangerous repo-local Git settings, validate resolved remote URL, disable hooks, and use explicit validated remote URL so repo config cannot redirect credentials.
- Tests may enable explicit test-only local-file transport; production defaults allow HTTPS/SSH only.

### 6. Add scoped authorization and metadata-only auditing

Update `internal/auth/authorize.go`, `metadata.go`, `token.go`, `store.go`, `internal/server/server.go`, and tool registration.

- Keep `workspace` base scope for existing/new bounded filesystem and read-Git tools. Add `workspace:exec`, `workspace:git-write`, `workspace:git-network`.
- Parse space-delimited scope sets, require `workspace`, accept only advertised enabled scopes, retain exact scopes through code/refresh exchange, return separate `TokenInfo.Scopes`. Include client ID in `TokenInfo.Extra` for async ownership.
- Advertise only runtime-enabled scopes. Consent UI names command execution, network access, local Git mutation, and remote push separately.
- Gate dangerous tools using `CallToolRequest.Extra.TokenInfo`; local mode uses runtime flags. Missing scope yields MCP tool error. Bearer middleware requires only base `workspace`.
- Audit dangerous calls with request/client identity, tool, argv/script digest, cwd, job ID, remote/ref names, result, duration, timeout/cancel, truncation. Never log source, output, environment values, tokens, keys, or commit message bodies.

### 7. Register tools with accurate MCP behavior

Split `internal/server/tools.go` into filesystem, execution, and Git registration groups.

- Preserve existing names and response compatibility.
- Use typed outputs. Invalid input and operation failure stay `isError` tool results, not JSON-RPC failures.
- Add titles and explicit annotations. Filesystem/local Git reads closed-world; mutations destructive as appropriate; `exec_*` and Git network `OpenWorldHint=true`; status/cancel reflect real side effects.
- Add `server_capabilities` reporting enabled features and numeric limits without paths/secrets. Do not rely on elicitation or client prompts for security.

### 8. Documentation and deployment hardening

Update `README.md`, `.env.example`, `scripts/start-tunnel.sh`, and `deploy/systemd/`.

- Document `bubblewrap`, `slirp4netns`, cgroup/systemd requirements, WSL2 checks, credential provisioning, OAuth reconnection after adding scopes, async lifetime, and enable flags.
- State arbitrary workspace code plus network is RCE-equivalent, can exfiltrate workspace contents, and should be exposed only to owner connector.
- Harden service with `NoNewPrivileges`, restrictive umask, protected system/home, private temp, bounded tasks/memory/CPU, and only sandbox-required namespaces. Ensure hardening does not block bwrap/user namespaces.

## Verification

1. Unit tests: config fail-closed probes, scope parsing/refresh, tool annotations/schemas, ref/remote validation, output/job bounds.
2. Workspace tests: traversal, absolute paths, `.git`, symlink/hard-link attacks, rename races, delete caps, patch prevalidation, atomic writes, glob bounds, ranged reads.
3. Sandbox integration: host home/OAuth state/credentials/sockets/env secrets invisible; workspace writable; outbound DNS/HTTPS works through private namespace; limits apply; output truncates; timeout/cancel kills descendants; owner/cursor/capacity/TTL enforcement.
4. Git integration against temporary repos and test-only bare remote: add/restore/commit/branch/switch/stash/fetch/pull/push; reject invalid refs/options/remotes; hooks cannot run during credential operations; general exec cannot read credentials; dedicated push can.
5. MCP server tests list/call every enabled/disabled profile and verify scope denial/success.
6. Run sequentially with project Go: `gofmt`, targeted tests, `go test ./...`, `CGO_ENABLED=1 go test -race ./...`, `go vet ./...`, `sh -n scripts/start-tunnel.sh`, `git diff --check`, build.
7. Launch safe and agentic profiles; smoke read/write/patch, short exec, async lifecycle, commit, sandbox escape denials.
8. Restart authenticated tunnel with `--agentic`, reconnect Claude.ai for scopes, run disposable inspect/edit/test/commit/push workflow, confirm metadata-only audit and OAuth/origin protections.
