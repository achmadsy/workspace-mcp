# In progress

Last commit: 4d8a286 "Display Quick Tunnel connector URL and credentials before detaching".
Working tree: modified files plus new `internal/workspace/ignore.go`, `ignore_test.go`,
`internal/server/capabilities_test.go`, and untracked `.claude/`. Nothing has been compiled or run
(no build access through the connector, no bwrap on the host).
Rule from the user: update this file after every step.

## Finished (all uncompiled)
- Ignore-aware `workspace_search`: `ignore.go`, `skipDir` wired in `search.go`, `.tools` in
  `ignoredDirectory`, `include_ignored` tool option, tests in `ignore_test.go`.
- `workspace_glob` returns `GlobResult{Paths, Truncated, TruncatedReason}` and truncates instead
  of erroring; tests in `operations_test.go`.
- `server_capabilities`: `buildCapabilities(cfg)` in `tools.go` adds exec/job timeouts, job TTL,
  memory/process/file/CPU limits, `exec_network`, `git_credential_mode` (name only); exec fields
  omitted when exec is off. Tests in `capabilities_test.go` (exec on, exec off, no paths leaked).
  plan.md updated.

## Now working on: audit logging for mutating workspace tools
Goal: workspace_write, workspace_edit, workspace_delete, workspace_move, workspace_copy,
workspace_mkdir and workspace_apply_patch are not audited today. Log path(s) and size only, never
content.
- [x] Step 1: found the mechanism. `auditTool(req, toolName, attrs ...any)` in `tools.go` (adds
      tool name and X-Request-ID, then logs); exec_* and git_* handlers call it with
      `"client_id", toolOwner(cfg, req)`. Workspace mutating handlers take `_ *mcp.CallToolRequest`
      and never call it.
- [x] Step 2: all seven mutating workspace handlers now call `auditWorkspace` (paths, byte
      counts, flags, changed, error; never content, edit text or patch text).
      - [x] helper `auditWorkspace(req, cfg, tool, err, attrs...)` added before `auditTool`
      - [x] write  - [x] edit  - [x] mkdir  - [x] delete  - [x] move  - [x] copy  - [x] apply_patch
      Note: `req` replaced `_` in each handler signature; `config` is already imported in
      `tools.go` (buildCapabilities and toolOwner use it).
- [x] Step 3: added `internal/server/audit_test.go`: drives mkdir, write, edit, copy, move,
      apply_patch and delete through `startTestServer`, captures `slog` output, asserts one entry
      per tool with `client_id=local` and `path=notes.txt`, and that no content/edit/patch secret
      appears. Swaps the default slog logger, so it is deliberately not parallel. plan.md updated.

Audit logging is complete (uncompiled).

## Now working on: README note on private network reach
- [x] Step 1: found `README.md`. Relevant spots: "Agentic execution" bullet in "## Security model"
      (says private namespace via slirp4netns "with host loopback blocked") and the warning box
      below it. Also found a stale claim in "## Tools": "Existing tool names and response shapes
      remain compatible", which is no longer true for `workspace_glob` ({paths, truncated}).
- [ ] Step 2: add a "Sandbox network reach" note after the warning box; add an audit bullet; fix
      the stale compatibility sentence.
- [ ] Step 3: update plan.md.

## Next steps
1. (in progress, see above) README network note.
2. Seccomp filter and optional egress policy: wait for a host with bwrap.

## Open points
- Confirm `config.go` already imports `exec` and `time` (used by `helpMentions`).
- Existing tests relying on search descending into `build`/`dist`/`target` are unaffected; `.tools`
  is new.
- `capabilities_test.go` assumes module path `github.com/link/workspace-mcp` and the `GitKnownHostsFile`
  field name seen in `config.go`; verify at build time.
- `audit_test.go` assumes `startTestServer`, `rpc` and the JSON field names of the tool inputs as
  seen in `tools.go`; the apply_patch call may fail on patch format, which the test tolerates.
- Run `go build ./... && go test ./...` on a capable host before committing.
