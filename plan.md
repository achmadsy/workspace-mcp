# Plan: Workspace MCP hardening and agent ergonomics

Source: review of runner.go, config.go, limits.go, tools.go and a live test of the connector.
Status key: [x] complete in the working tree (uncommitted), [~] partly done, [ ] not started.
The full build and test suite pass with the project Go 1.25 toolchain. Live sandbox startup and
`exec_run` also pass on the WSL2 host with bubblewrap 0.6.1 and slirp4netns 1.0.1.

## 1. Bugs that break normal use
- [x] `--fsize` was `ExecMaxOutput*2` (1 MiB). Now its own setting, `MCP_EXEC_MAX_FILE_BYTES`
      (default 1 GiB, valid range 1 MiB to 1 TiB).
- [x] Dropped `--as` (address space is not memory). Rely on cgroup `MemoryMax`, add
      `MemorySwapMax=0`, default memory raised to 2 GiB.
- [x] Dropped `--nproc` (counted per real UID, includes the server). `TasksMax` on the scope
      bounds the sandbox; default 512.
- [x] Synthetic `/etc` via memfd: passwd, group, hosts, nsswitch.conf, and resolv.conf
      (`nameserver 10.0.2.3`) only when networking is on. Host resolv.conf is no longer reused.
- [x] `workspace_search` at the root exhausted its budget in gitignored trees (e.g. `.tools/go`).
      Now skips built-in ignored dirs (incl. `.tools`) and simple root `.gitignore` patterns
      (`ignore.go`), reports `truncated_reason` and `skipped_dirs`, and has an `include_ignored`
      option on the tool. Compiled and tested.

## 2. Security hardening
- [x] bwrap: `--cap-drop ALL`; `--unshare-user --disable-userns` only when `bwrap --help`
      mentions it (probed at startup).
- [x] slirp4netns: `--enable-sandbox` / `--enable-seccomp`, each probed at startup. On the exact
      intermittent `setegid(0) ... parent failed` mount-sandbox failure, startup retries the full
      isolation self-test without that layer while retaining seccomp; unrelated failures remain
      fail-closed.
- [x] Cleanup backstop: `systemdCommand` returns the unit name; `systemctl --user kill
      --signal=SIGKILL <unit>.scope` on timeout, cancel and handshake failure.
- [ ] Seccomp filter for the sandbox (needs a capable host to validate).
- [x] README: new "Sandbox network reach" section says `--disable-host-loopback` does not block
      LAN, RFC1918 or 169.254.169.254, and points to host-level egress rules. Optional later:
      opt-in egress policy (not implemented).
- [x] Audit gaps: workspace_write, edit, mkdir, delete, move, copy and apply_patch now log via
      `auditWorkspace` (client_id, paths, byte counts, changed, error; never content). End-to-end
      test in `internal/server/audit_test.go`.

## 3. Better for the agent
- [x] Head+tail buffer for synchronous runs (a quarter head, rest tail, omission marker).
- [x] Rolling buffer for jobs with absolute cursors and `stdout_dropped_bytes` /
      `stderr_dropped_bytes`.
- [x] Search results carry `truncated_reason` and a sample of `skipped_dirs`.
- [x] `workspace_glob`: returns `{paths, truncated, truncated_reason}`; hitting the scan or result
      limit now returns the sorted partial list instead of an error. Tests added.
- [x] `server_capabilities`: now reports exec and job timeouts, memory, process, file-size and CPU
      limits, job TTL, `exec_network`, and `git_credential_mode` (name only). Built by
      `buildCapabilities`; exec fields omitted when exec is off. Tests in `capabilities_test.go`.

## 4. Tests
- [x] Config bounds and defaults, `envBoolDefault`.
- [x] Golden test for `commandArgs` hardening (no credential mounts in general exec, clean env,
      `/etc` fd numbering with and without network).
- [x] `systemdCommand` limits test, `limitBuffer` head+tail and rolling cursor tests.
- [x] Startup self-test now asserts isolation (exit codes 11 to 16) rather than running `/bin/true`.
- [x] Tests for ignore rules, `IncludeIgnored` and truncation reason (`ignore_test.go`).
- [x] Tests for the new glob and capabilities shapes (`operations_test.go`, `capabilities_test.go`),
      and audit logging (`audit_test.go`). All pass.

## 5. Cleanup
- [x] `RunGitNetwork` credential-mode check rewritten explicitly (`hasSSH && hasHTTPS`).

## 6. Re-review backlog (agentic coding), not started
Bugs:
- [x] `Jobs.Start` counts finished jobs against `ExecMaxJobs` until the 30 min TTL, so 8 finished
      `exec_start` jobs lock out new ones ("job capacity reached"). Fixed: oldest finished job is
      evicted when full; test added. Uncompiled.
- [~] The intermittent `setegid(0) ... parent failed` slirp failure is retried only at startup.
      Later `exec_run` calls can hit it and fail. Likely a race: slirp4netns joins the userns before
      bwrap has written the uid/gid maps (unconfirmed). Fixed by bounded per-request retry
      (`startNetworkWithRetry`), uncompiled. Still open: report any startup downgrade in
      `server_capabilities`.
- [x] `ApplyPatch`: pure-insert hunks (`-N,0`) were positioned one line early. Fixed with
      `hunkPosition`; test added. Uncompiled.
Ergonomics:
- [ ] `exec_run` default timeout 15 s is too short for builds/tests; `exec_status` has no
      wait/long-poll (`wait_ms`), so agents burn turns polling.
- [ ] Sandbox `/home` and `/tmp` are tmpfs, so Go/npm/pip/cargo caches are lost every call. Add a
      persistent cache dir (GOCACHE, GOMODCACHE, npm, pip) outside the workspace tree.
- [~] `LC_ALL=C` / `LANG=C` changed to `C.UTF-8` (uncompiled). Still open: `PATH` cannot be set, so workspace toolchains
      (`.tools/go/bin`) need a script; add a config-defined PATH prefix.
- [ ] `CPUQuota=100%` is hard-coded; make it configurable. Add `oom_killed` to results.
- [ ] Optional per-request `network:false` for hermetic tests; `exec_network` is always on.
- [ ] `workspace_apply_patch`: no create/delete/rename, exact line numbers only, blank context
      lines without a leading space rejected. Add offset/fuzz matching and create/delete.
- [ ] `git_diff` is unstaged only with no path or revision args; add staged and per-path diff.
- [ ] `workspace_read`: no line numbers or line-range read; error "file is unavailable or unsafe"
      does not say not-found vs symlink vs permission. `workspace_edit` has no replace_all.
- [ ] No structured test/lint runner (parsed failures) and no stdin for jobs.
Security notes:
- [ ] Write/delete/patch share the base `workspace` scope with read; consider `workspace:write`.
- [ ] Startup self-test does not exercise networking (DNS/connect through slirp).

## 7. Re-review 2 (2026-10-08, after the build/test pass). Not implemented; needs approval.
Section 6 steps 1 to 5 compile and pass tests at HEAD 4c5dfcc, so the "uncompiled" and "uncommitted"
notes above are stale. Items marked (live) were observed while using this connector today.
Bugs and risks, in priority order:
- [x] A (live). Network start failures beyond one known signature. 3 of about 8 `exec_run` calls
      failed with `isolated network helper closed its readiness pipe (stderr: setns(CLONE_NEWNET):
      Operation not permitted | child failed(1))` and passed on an immediate retry. The retry
      predicate only matches `setegid(0)` + `parent failed`, so `startNetworkWithRetry` never
      engaged and the agent got a hard error. Fix: one shared allowlist predicate (both
      signatures), used by the per-request retry and by `shouldRetryWithoutSlirpSandbox`; keep
      the bound at 3 and only retry while the sandbox is still blocked; log attempt count and
      helper stderr to find the real root cause (unconfirmed). Tests for both strings.
      Done: `isTransientNetworkStartFailure` is an allowlist (`slirpMountSandboxFailure`,
      `slirpNamespaceJoinFailure`), 5 attempts (50 to 200 ms backoff), attempt count in logs and in
      the final error. Deviation: the startup downgrade (`shouldRetryWithoutSlirpSandbox`) stays
      limited to the mount-sandbox signature, because a namespace join failure is not evidence
      against that layer and must never weaken hardening. Needs a server restart to take effect.
- [x] B. `evictOldestTerminalLocked` can delete a finished job whose output was never read, so
      the agent sees "not found" for a job that succeeded. Fix: cap only running and queued jobs
      at `ExecMaxJobs`, keep finished jobs in a separate bounded ring (e.g. 32) with the TTL, and
      prefer evicting jobs already read to the end. Keep a tombstone (state, exit_code) so
      `exec_status` can say "evicted".
      Done in `jobs.go`: only queued and running jobs count against `ExecMaxJobs`; finished jobs
      are trimmed to 32 (read ones first, then oldest unread); 256 bounded tombstones give
      "job output is no longer available: <reason> (state, exit code)" to the owning client.
- [ ] C. Scope expansion is all-or-nothing. A bare `workspace` request now grants exec, git write
      and git network to any client the owner approves, and the consent page shows one long
      string. Better: consent page with a checkbox per scope (`workspace` fixed on, others
      default from config), token records exactly what was ticked (the token response already
      returns `scope`). `st.Consents` is written but never read: use it or delete it.
- [ ] D. Login rate limit is keyed by `RemoteAddr` (`clientIP`). Behind a local tunnel every
      caller likely shares one bucket, so bad-password spam can lock the owner out (unconfirmed
      for this deployment). Fix: trust `CF-Connecting-IP` only when the peer is loopback, add a
      global cap, and confirm the attempts map is pruned.
- [ ] E. No cap found by grep on `Pending` or `Clients` records created by unauthenticated
      `/authorize` and `/register`, each persisted to the state file. Confirm in store.go and
      registration.go, then add caps and TTL pruning.
- [x] F. `gofmt -l` flags `internal/auth/authorize.go`. `startNetworkWithRetry` returns
      `(*networkProcess, error, error)` (error not last): use a result struct. Add `gofmt -l`
      and `go vet` to a check script. Done: `scripts/check.sh` (gofmt, vet, tests, umask 022).
- [x] G. `TestSecureCredentialFile` and `TestCredentialBrokerRejectsUnsafeFiles` fail under umask
      0077 (the sandbox default). `os.Chmod` after `WriteFile`.
- [x] H. `.claude/` is untracked and holds `settings.local.json`; add it to `.gitignore`.
Agent ergonomics (live evidence):
- [ ] Persistent caches. `go: downloading golang.org/x/sys` ran on every call and a cold build took
      about 25 s, because `/tmp` and `/home` are tmpfs. Add a server-owned cache dir mounted
      read-write at `/cache` with `GOCACHE`, `GOMODCACHE`, npm and pip defaults. The cache is
      writable by sandboxed code, so treat it as the same trust level as the workspace.
- [ ] `exec_status` long poll: `wait_ms` (capped, returns on completion or new output). A 22 s
      job took about 12 polls.
- [ ] Discoverability. The sandbox default Go is 1.20.7 and cannot parse this project's go.mod;
      the agent had to find `.tools/go` by trial. Add a configured PATH prefix, report it in
      `server_capabilities`, and say the sync timeout limit in the "exceeds synchronous limit"
      error (also expose it as a capability). Consider umask 022 for sandbox processes.
- [ ] `workspace_apply_patch`: ignore header line numbers and locate hunks by context with a small
      fuzz, plus create and delete. A hand-counted patch failed with "hunk context does not
      match" today.
Suggested order: A, B, then F, G, H (cheap), then persistent cache and `wait_ms` (largest
ergonomic win), then C, D, E (security), then patch fuzz.

## Order of work
1. Finish ignore rules and make the workspace package compile.
2. Glob result shape and `server_capabilities`.
3. Audit logging for mutating workspace tools.
4. README notes. Seccomp and egress policy wait for a host with bwrap.
5. [x] Run `go build ./... && go test ./...` on a capable host before committing.
