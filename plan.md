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

## Order of work
1. Finish ignore rules and make the workspace package compile.
2. Glob result shape and `server_capabilities`.
3. Audit logging for mutating workspace tools.
4. README notes. Seccomp and egress policy wait for a host with bwrap.
5. [x] Run `go build ./... && go test ./...` on a capable host before committing.
