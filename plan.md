# Plan: Workspace MCP hardening and agent ergonomics

Source: review of runner.go, config.go, limits.go, tools.go and a live test of the connector.
Status key: [x] edited in the working tree (uncommitted, not compiled or tested: the connector
cannot run builds and the host has no bwrap), [~] partly done, [ ] not started.

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
      option on the tool. Not compiled or tested yet.

## 2. Security hardening
- [x] bwrap: `--cap-drop ALL`; `--unshare-user --disable-userns` only when `bwrap --help`
      mentions it (probed at startup).
- [x] slirp4netns: `--enable-sandbox` / `--enable-seccomp`, each probed at startup.
- [x] Cleanup backstop: `systemdCommand` returns the unit name; `systemctl --user kill
      --signal=SIGKILL <unit>.scope` on timeout, cancel and handshake failure.
- [ ] Seccomp filter for the sandbox (needs a capable host to validate).
- [ ] Document that `--disable-host-loopback` does not block LAN, RFC1918 or 169.254.169.254
      (README). Optional later: opt-in egress policy.
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
- [ ] Tests for the new glob and capabilities shapes.

## 5. Cleanup
- [x] `RunGitNetwork` credential-mode check rewritten explicitly (`hasSSH && hasHTTPS`).

## Order of work
1. Finish ignore rules and make the workspace package compile.
2. Glob result shape and `server_capabilities`.
3. Audit logging for mutating workspace tools.
4. README notes. Seccomp and egress policy wait for a host with bwrap.
5. Run `go build ./... && go test ./...` on a capable host before committing.
