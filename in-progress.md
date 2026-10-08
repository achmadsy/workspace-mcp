# In progress

Last commit: c97b171 "inprogress".
Working tree: user changes remain uncommitted; this pass changed `internal/sandboxexec/runner.go`,
`internal/sandboxexec/runner_test.go`, `plan.md`, and this file.
Rule from the user: update this file after every step.

## Finished
- Ignore-aware `workspace_search`: built-in and simple root `.gitignore` exclusions,
  `include_ignored`, `truncated_reason`, `skipped_dirs`, and tests.
- `workspace_glob`: structured partial results with truncation metadata and tests.
- Expanded `server_capabilities` and tests.
- Audit logging for all mutating workspace tools and end-to-end tests.
- README response-shape, audit, and sandbox network notes.
- Sandbox hardening, limits, cleanup backstop, output buffers, and associated tests.

## Sandbox startup fix
- Added handshake failure annotation with process status and bounded stderr.
- Confirmed original startup failure:
  `bwrap: Can't find source path /proc/self/fd/6: No such file or directory`.
- Root cause: generated `/etc` files and Git credentials used pathname mounts from
  `/proc/self/fd/N`. Bubblewrap resolves memfd magic links to deleted anonymous paths before
  mounting, so descriptor 6 disappeared as a usable pathname.
- Fixed workspace mounting with `--bind-fd` and data/credential mounting with
  `--ro-bind-data`, including explicit destination permissions.
- Added targeted command-argument tests for fd-native mounts.
- slirp4netns 1.0.1 mount sandboxing fails intermittently on this WSL2 host with
  `setegid(0) ... parent failed`. Startup retries the full isolation self-test without only
  `--enable-sandbox` for that exact signature, retains `--enable-seccomp`, and logs the downgrade.
  Unrelated failures remain fail-closed.

## Verification
- `go test ./internal/sandboxexec`: pass.
- `go build ./...`: pass with project Go 1.25.0 toolchain.
- `go test ./...`: pass for every package.
- Three consecutive live agentic startups on WSL2 with bubblewrap 0.6.1 and slirp4netns 1.0.1:
  all pass. Runs 1 and 3 used full slirp hardening; run 2 hit the exact intermittent failure,
  retried without only `--enable-sandbox`, retained seccomp, and passed.
- MCP `initialize`: pass on all three runs.
- Real MCP `exec_run`: pass on all three runs; each sandbox read synthetic `/etc/passwd`, wrote a
  workspace probe file, read it back as `sandbox-ok`, and removed it.

## Re-review (read-only pass, 2026-10-08)
- Read plan.md, in-progress.md, git status/diff, tools.go, runner.go, jobs.go, patch.go, read.go.
- Could not run build/tests: this connector token lacks `workspace:exec`, so the "all tests pass"
  claims above were not re-verified in this pass.
- Findings are recorded as section 6 of plan.md (nothing in the code was changed).

## Implementation of plan.md section 6 (approved by the user)
Build and tests cannot run from this connector (no `workspace:exec`), so every change below is
uncompiled and untested. Run `go build ./... && go test ./...` before committing.
- [x] Step 1: job slot leak. `Jobs.Start` now calls `evictOldestTerminalLocked` when full, so
      finished jobs no longer block new ones; running jobs are never evicted. Added
      `TestJobsEvictsOldestFinishedJobWhenFull` in `jobs_test.go`.
- [x] Step 2: `-U0` patches. `applyHunks` now uses `hunkPosition` so zero-count ranges
      (pure insert/delete) are placed after the line named in the header. Added
      `TestApplyPatchZeroContextHunks` in `operations_test.go`.
- [x] Step 3: slirp start failures. New `startNetworkWithRetry` in `runner.go` retries the known
      `setegid(0) ... parent failed` failure up to 3 times (50 ms, 100 ms backoff) with the same
      hardening while the sandbox is held on the block-fd. Helper stderr is captured per attempt
      and appended to the command stderr buffer only when the final attempt fails, so a recovered
      retry leaves no stale text; a side effect is that slirp4netns runtime warnings no longer
      appear in command stderr. Other failures are not retried. The startup downgrade fallback is
      kept. Added `TestIsTransientNetworkStartFailure`. Not done: reporting the downgrade in
      `server_capabilities`.
- [x] Step 4: sandbox locale. `buildEnvironment` now sets `LC_ALL`/`LANG` to `C.UTF-8` (was `C`)
      so Python and other tools emit UTF-8. Git service keeps `C` for stable output parsing.
- [x] Step 5: OAuth scope expansion. claude.ai requests only `workspace`, so tokens never carried
      `workspace:exec` (exec_* failed with "missing authorization scope"). Added
      `Server.grantedScope` in `internal/auth/authorize.go`: a bare `workspace` request is expanded
      to every enabled scope before it is stored on the pending authorization; explicit scope
      requests are unchanged. The consent page prints the expanded list. Added
      `TestGrantedScopeExpandsBareWorkspace` in `auth_test.go`. Uncompiled. Needs rebuild, server
      restart and re-adding the connector (existing tokens keep their old scope). Trade-off: no
      per-scope choice for clients that ask for plain `workspace`.

## Remaining
- Review diff and commit when requested.
- Seccomp filter for sandboxed workload itself remains optional future work; current slirp4netns
  helper seccomp is enabled where supported.
- Optional host-level egress policy remains future work.
