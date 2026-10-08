package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/link/workspace-mcp/internal/config"
	gitservice "github.com/link/workspace-mcp/internal/git"
	"github.com/link/workspace-mcp/internal/limits"
	"github.com/link/workspace-mcp/internal/sandboxexec"
	"github.com/link/workspace-mcp/internal/workspace"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listInput struct {
	Path  string `json:"path,omitempty" jsonschema:"Relative directory path; omit for workspace root"`
	Depth int    `json:"depth,omitempty" jsonschema:"Traversal depth (1-8); default 2"`
}
type readInput struct {
	Path string `json:"path" jsonschema:"Relative UTF-8 text file path"`
}
type readRangeInput struct {
	Path   string `json:"path" jsonschema:"Relative UTF-8 text file path"`
	Offset int64  `json:"offset" jsonschema:"Zero-based byte offset"`
	Length int64  `json:"length" jsonschema:"Maximum bytes to return"`
}
type globInput struct {
	Pattern string `json:"pattern" jsonschema:"Slash-separated glob pattern"`
	Path    string `json:"path,omitempty" jsonschema:"Relative directory below which to match"`
}
type searchInput struct {
	Query           string   `json:"query" jsonschema:"Literal text to find"`
	Path            string   `json:"path,omitempty" jsonschema:"Relative file or directory; omit for workspace root"`
	MaxResults      int      `json:"max_results,omitempty" jsonschema:"Maximum matches (1-200); default 50"`
	CaseInsensitive bool     `json:"case_insensitive,omitempty" jsonschema:"Match without case sensitivity"`
	Include         []string `json:"include,omitempty" jsonschema:"Optional file glob allowlist"`
	ContextLines    int      `json:"context_lines,omitempty" jsonschema:"Lines before and after each match (0-20)"`
	IncludeIgnored  bool     `json:"include_ignored,omitempty" jsonschema:"Also search ignored directories (node_modules, vendor, .tools, root .gitignore entries); default false"`
}
type writeInput struct {
	Path    string `json:"path" jsonschema:"Relative destination path"`
	Content string `json:"content" jsonschema:"Complete UTF-8 file content"`
}
type editInput struct {
	Path    string `json:"path" jsonschema:"Relative file path"`
	OldText string `json:"old_text" jsonschema:"Exact non-empty text that must occur exactly once"`
	NewText string `json:"new_text" jsonschema:"Replacement text"`
}
type mkdirInput struct {
	Path    string `json:"path" jsonschema:"Relative directory path"`
	Parents bool   `json:"parents,omitempty" jsonschema:"Create missing parent directories"`
}
type deleteInput struct {
	Path      string `json:"path" jsonschema:"Relative file or directory path"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"Required for directory deletion"`
}
type moveInput struct {
	Source      string `json:"source" jsonschema:"Relative source path"`
	Destination string `json:"destination" jsonschema:"Relative destination path"`
	Overwrite   bool   `json:"overwrite,omitempty" jsonschema:"Allow replacing a safe destination"`
}
type patchInput struct {
	Patch string `json:"patch" jsonschema:"Unified diff for existing UTF-8 workspace files"`
}
type execInput = sandboxexec.Request
type jobStatusInput struct {
	ID           string `json:"id" jsonschema:"Job ID"`
	StdoutCursor int    `json:"stdout_cursor,omitempty" jsonschema:"Previously returned stdout cursor"`
	StderrCursor int    `json:"stderr_cursor,omitempty" jsonschema:"Previously returned stderr cursor"`
	WaitMS       int    `json:"wait_ms,omitempty" jsonschema:"Wait up to this many milliseconds for the job to finish or produce new output before answering; capped at the server exec timeout"`
}
type jobInput struct {
	ID string `json:"id" jsonschema:"Job ID"`
}
type logInput struct {
	MaxCount int `json:"max_count,omitempty" jsonschema:"Maximum commits (1-200); default 20"`
}
type showInput struct {
	Revision string `json:"revision" jsonschema:"Validated branch name, commit ID, or HEAD"`
}
type pathsInput struct {
	Paths []string `json:"paths" jsonschema:"Relative workspace paths"`
}
type restoreInput struct {
	Paths  []string `json:"paths" jsonschema:"Relative workspace paths"`
	Staged bool     `json:"staged,omitempty" jsonschema:"Restore from index and unstage paths"`
}
type messageInput struct {
	Message string `json:"message" jsonschema:"Commit message"`
}
type branchInput struct {
	Name       string `json:"name" jsonschema:"New branch name"`
	StartPoint string `json:"start_point,omitempty" jsonschema:"Optional validated branch, commit ID, or HEAD"`
}
type switchInput struct {
	Branch string `json:"branch" jsonschema:"Existing branch name"`
}
type stashPushInput struct {
	Message          string `json:"message,omitempty" jsonschema:"Optional stash message"`
	IncludeUntracked bool   `json:"include_untracked,omitempty" jsonschema:"Include untracked files"`
}
type stashPopInput struct {
	Index int `json:"index,omitempty" jsonschema:"Stash index; default 0"`
}
type remoteInput struct {
	Remote string `json:"remote" jsonschema:"Configured allowed remote name"`
}
type pullInput struct {
	Remote string `json:"remote" jsonschema:"Configured allowed remote name"`
	Branch string `json:"branch" jsonschema:"Remote branch name"`
}
type pushInput struct {
	Remote         string `json:"remote" jsonschema:"Configured allowed remote name"`
	Refspec        string `json:"refspec" jsonschema:"Validated source or source:destination refspec"`
	ForceWithLease bool   `json:"force_with_lease,omitempty" jsonschema:"Use force-with-lease instead of a normal push"`
}
type noInput struct{}

type capabilitiesResult struct {
	Exec       bool `json:"exec"`
	GitWrite   bool `json:"git_write"`
	GitNetwork bool `json:"git_network"`
	// ExecNetwork reports whether sandboxed exec commands get a private network
	// (slirp4netns). It does not restrict LAN, RFC1918 or link-local addresses.
	ExecNetwork bool `json:"exec_network"`
	// GitCredentialMode is the mode name only ("none", "ssh_key", "https_token"), never paths.
	GitCredentialMode string `json:"git_credential_mode,omitempty"`
	Limits            struct {
		MaxFileBytes  int `json:"max_file_bytes"`
		MaxExecOutput int `json:"max_exec_output"`
		MaxExecJobs   int `json:"max_exec_jobs"`
		// Execution limits are reported only when exec is enabled.
		ExecTimeoutMS    int64  `json:"exec_timeout_ms,omitempty"`
		ExecJobTimeoutMS int64  `json:"exec_job_timeout_ms,omitempty"`
		ExecJobTTLSecs   int64  `json:"exec_job_ttl_seconds,omitempty"`
		ExecMemoryBytes  uint64 `json:"exec_memory_bytes,omitempty"`
		ExecMaxProcesses uint64 `json:"exec_max_processes,omitempty"`
		ExecMaxFileBytes uint64 `json:"exec_max_file_bytes,omitempty"`
		ExecCPUSeconds   uint64 `json:"exec_cpu_seconds,omitempty"`
	} `json:"limits"`
}

// buildCapabilities reports enabled gates and public limits. It never includes
// paths or secrets; credential mode is only the mode name.
func buildCapabilities(cfg config.Config) capabilitiesResult {
	out := capabilitiesResult{Exec: cfg.EnableExec, GitWrite: cfg.EnableGitWrite, GitNetwork: cfg.EnableGitNetwork}
	out.Limits.MaxFileBytes = limits.MaxFileBytes
	out.Limits.MaxExecOutput = cfg.ExecMaxOutput
	out.Limits.MaxExecJobs = cfg.ExecMaxJobs
	if cfg.EnableExec {
		out.ExecNetwork = true
		out.Limits.ExecTimeoutMS = cfg.ExecTimeout.Milliseconds()
		out.Limits.ExecJobTimeoutMS = cfg.ExecJobTimeout.Milliseconds()
		out.Limits.ExecJobTTLSecs = int64(cfg.ExecJobTTL / time.Second)
		out.Limits.ExecMemoryBytes = cfg.ExecMemoryBytes
		out.Limits.ExecMaxProcesses = cfg.ExecMaxProcesses
		out.Limits.ExecMaxFileBytes = cfg.ExecMaxFileBytes
		out.Limits.ExecCPUSeconds = cfg.ExecCPUSeconds
	}
	if cfg.EnableGitNetwork {
		out.GitCredentialMode = cfg.GitCredentialMode
	}
	return out
}

func registerTools(s *mcp.Server, cfg config.Config, ws *workspace.Root, gs *gitservice.Service, runner *sandboxexec.Runner, jobs *sandboxexec.Jobs) {
	readOnly, closed, open := true, false, true
	destructive, nonDestructive := true, false

	mcp.AddTool(s, tool("server_capabilities", "Report enabled capability gates and public numeric limits.", "Show server capabilities", readOnly, &nonDestructive, true, &closed),
		func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, capabilitiesResult, error) {
			return nil, buildCapabilities(cfg), nil
		})
	mcp.AddTool(s, tool("workspace_list", "List bounded workspace entries in deterministic lexical order. Symlinks and .git are never exposed.", "List workspace entries", readOnly, &nonDestructive, true, &closed),
		func(_ context.Context, _ *mcp.CallToolRequest, in listInput) (*mcp.CallToolResult, workspace.ListResult, error) {
			out, err := ws.List(in.Path, in.Depth)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_read", "Read one bounded UTF-8 regular file.", "Read workspace file", readOnly, &nonDestructive, true, &closed),
		func(_ context.Context, _ *mcp.CallToolRequest, in readInput) (*mcp.CallToolResult, workspace.ReadResult, error) {
			out, err := ws.Read(in.Path)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_stat", "Report type, size, mode, and modification time without following symlinks.", "Stat workspace path", readOnly, &nonDestructive, true, &closed),
		func(_ context.Context, _ *mcp.CallToolRequest, in readInput) (*mcp.CallToolResult, workspace.StatResult, error) {
			out, err := ws.Stat(in.Path)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_read_range", "Read a bounded UTF-8 byte range from one regular file.", "Read workspace range", readOnly, &nonDestructive, true, &closed),
		func(_ context.Context, _ *mcp.CallToolRequest, in readRangeInput) (*mcp.CallToolResult, workspace.RangeResult, error) {
			out, err := ws.ReadRange(in.Path, in.Offset, in.Length)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_glob", "Match a bounded deterministic slash-separated glob below a workspace directory. Returns paths plus a truncated flag and reason when a limit was hit.", "Glob workspace paths", readOnly, &nonDestructive, true, &closed),
		func(_ context.Context, _ *mcp.CallToolRequest, in globInput) (*mcp.CallToolResult, workspace.GlobResult, error) {
			out, err := ws.Glob(in.Pattern, in.Path)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_search", "Search literal text with optional case-insensitive matching, include globs, and context lines.", "Search workspace text", readOnly, &nonDestructive, true, &closed),
		func(ctx context.Context, _ *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, workspace.SearchResult, error) {
			ctx, cancel := context.WithTimeout(ctx, limits.ToolTimeout)
			defer cancel()
			out, err := ws.SearchWithOptions(ctx, in.Query, workspace.SearchOptions{Path: in.Path, MaxResults: in.MaxResults, CaseInsensitive: in.CaseInsensitive, Include: in.Include, ContextLines: in.ContextLines, IncludeIgnored: in.IncludeIgnored})
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_write", "Atomically create or replace one UTF-8 workspace file.", "Write workspace file", false, &destructive, false, &closed),
		func(_ context.Context, req *mcp.CallToolRequest, in writeInput) (*mcp.CallToolResult, workspace.WriteResult, error) {
			out, err := ws.Write(in.Path, in.Content)
			auditWorkspace(req, cfg, "workspace_write", err, "path", in.Path, "bytes", len(in.Content), "size", out.Size, "changed", out.Changed)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_edit", "Atomically replace exactly one occurrence in one UTF-8 workspace file.", "Edit workspace file", false, &destructive, false, &closed),
		func(_ context.Context, req *mcp.CallToolRequest, in editInput) (*mcp.CallToolResult, workspace.EditResult, error) {
			out, err := ws.Edit(in.Path, in.OldText, in.NewText)
			auditWorkspace(req, cfg, "workspace_edit", err, "path", in.Path, "old_bytes", len(in.OldText), "new_bytes", len(in.NewText), "size", out.Size, "changed", out.Changed)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_mkdir", "Create one safe workspace directory and optionally missing parents.", "Create workspace directory", false, &nonDestructive, true, &closed),
		func(_ context.Context, req *mcp.CallToolRequest, in mkdirInput) (*mcp.CallToolResult, workspace.MutationResult, error) {
			out, err := ws.Mkdir(in.Path, in.Parents)
			auditWorkspace(req, cfg, "workspace_mkdir", err, "path", in.Path, "parents", in.Parents, "changed", out.Changed)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_delete", "Delete one safe file or a fully prevalidated bounded directory tree.", "Delete workspace path", false, &destructive, true, &closed),
		func(_ context.Context, req *mcp.CallToolRequest, in deleteInput) (*mcp.CallToolResult, workspace.MutationResult, error) {
			out, err := ws.Delete(in.Path, in.Recursive)
			auditWorkspace(req, cfg, "workspace_delete", err, "path", in.Path, "recursive", in.Recursive, "changed", out.Changed)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_move", "Atomically move one safe file or directory inside the workspace.", "Move workspace path", false, &destructive, false, &closed),
		func(_ context.Context, req *mcp.CallToolRequest, in moveInput) (*mcp.CallToolResult, workspace.MoveResult, error) {
			out, err := ws.Move(in.Source, in.Destination, in.Overwrite)
			auditWorkspace(req, cfg, "workspace_move", err, "source", in.Source, "destination", in.Destination, "overwrite", in.Overwrite, "changed", out.Changed)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_copy", "Atomically copy one regular single-linked file inside the workspace.", "Copy workspace file", false, &nonDestructive, true, &closed),
		func(_ context.Context, req *mcp.CallToolRequest, in moveInput) (*mcp.CallToolResult, workspace.MoveResult, error) {
			out, err := ws.Copy(in.Source, in.Destination, in.Overwrite)
			auditWorkspace(req, cfg, "workspace_copy", err, "source", in.Source, "destination", in.Destination, "overwrite", in.Overwrite, "changed", out.Changed)
			return nil, out, err
		})
	mcp.AddTool(s, tool("workspace_apply_patch", "Prevalidate and apply a unified diff to existing UTF-8 workspace files.", "Apply workspace patch", false, &destructive, false, &closed),
		func(_ context.Context, req *mcp.CallToolRequest, in patchInput) (*mcp.CallToolResult, workspace.PatchResult, error) {
			out, err := ws.ApplyPatch(in.Patch)
			auditWorkspace(req, cfg, "workspace_apply_patch", err, "patch_bytes", len(in.Patch), "files_changed", out.FilesChanged, "path_count", len(out.Paths))
			return nil, out, err
		})

	registerGitReadTools(s, gs, readOnly, nonDestructive, closed)
	if cfg.EnableExec {
		registerExecTools(s, cfg, runner, jobs, open)
	}
	if cfg.EnableGitWrite {
		registerGitWriteTools(s, cfg, gs, closed)
	}
	if cfg.EnableGitNetwork {
		registerGitNetworkTools(s, cfg, gs, open)
	}
}

func registerExecTools(s *mcp.Server, cfg config.Config, runner *sandboxexec.Runner, jobs *sandboxexec.Jobs, open bool) {
	destructive := true
	mcp.AddTool(s, tool("exec_run", "Run one short command inside the mandatory isolated sandbox with outbound network access.", "Run sandbox command", false, &destructive, false, &open),
		func(ctx context.Context, req *mcp.CallToolRequest, in execInput) (*mcp.CallToolResult, sandboxexec.Result, error) {
			if err := requireScope(cfg, req, "workspace:exec"); err != nil {
				return nil, sandboxexec.Result{}, err
			}
			if in.TimeoutMS > int(cfg.ExecTimeout/time.Millisecond) {
				return nil, sandboxexec.Result{}, errors.New("exec_run timeout exceeds synchronous limit; use exec_start")
			}
			out, err := runner.Run(ctx, in, nil)
			auditTool(req, "exec_run", "client_id", toolOwner(cfg, req), "command_digest", commandDigest(in), "cwd", in.Cwd, "exit_code", out.ExitCode, "duration_ms", out.DurationMS, "timed_out", out.TimedOut, "canceled", out.Canceled, "stdout_truncated", out.StdoutTruncated, "stderr_truncated", out.StderrTruncated, "error", err != nil)
			return nil, out, err
		})
	mcp.AddTool(s, tool("exec_start", "Start one long-running sandbox command and return an owner-bound job ID.", "Start sandbox job", false, &destructive, false, &open),
		func(_ context.Context, req *mcp.CallToolRequest, in execInput) (*mcp.CallToolResult, sandboxexec.JobStatus, error) {
			if err := requireScope(cfg, req, "workspace:exec"); err != nil {
				return nil, sandboxexec.JobStatus{}, err
			}
			owner := toolOwner(cfg, req)
			out, err := jobs.Start(owner, in)
			auditTool(req, "exec_start", "client_id", owner, "command_digest", commandDigest(in), "cwd", in.Cwd, "job_id", out.ID, "error", err != nil)
			return nil, out, err
		})
	mcp.AddTool(s, tool("exec_status", "Read retained incremental output and status for an owner-bound sandbox job. Pass wait_ms to wait for completion or new output instead of polling.", "Show sandbox job", true, nil, true, &open),
		func(ctx context.Context, req *mcp.CallToolRequest, in jobStatusInput) (*mcp.CallToolResult, sandboxexec.JobStatus, error) {
			if err := requireScope(cfg, req, "workspace:exec"); err != nil {
				return nil, sandboxexec.JobStatus{}, err
			}
			out, err := jobs.Wait(ctx, toolOwner(cfg, req), in.ID, in.StdoutCursor, in.StderrCursor, time.Duration(in.WaitMS)*time.Millisecond)
			return nil, out, err
		})
	mcp.AddTool(s, tool("exec_cancel", "Cancel an owner-bound sandbox job and its descendants.", "Cancel sandbox job", false, &destructive, true, &open),
		func(_ context.Context, req *mcp.CallToolRequest, in jobInput) (*mcp.CallToolResult, sandboxexec.JobStatus, error) {
			if err := requireScope(cfg, req, "workspace:exec"); err != nil {
				return nil, sandboxexec.JobStatus{}, err
			}
			owner := toolOwner(cfg, req)
			out, err := jobs.Cancel(owner, in.ID)
			auditTool(req, "exec_cancel", "client_id", owner, "job_id", in.ID, "state", out.State, "error", err != nil)
			return nil, out, err
		})
}

func registerGitReadTools(s *mcp.Server, gs *gitservice.Service, readOnly, nonDestructive, closed bool) {
	add := func(name, description, title string, handler func(context.Context) (gitservice.Result, error)) {
		mcp.AddTool(s, tool(name, description, title, readOnly, &nonDestructive, true, &closed), func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, gitservice.Result, error) {
			out, err := handler(ctx)
			return nil, out, err
		})
	}
	add("git_status", "Show bounded short Git status.", "Show git status", gs.Status)
	add("git_diff", "Show bounded unstaged Git diff with external helpers disabled.", "Show git diff", gs.Diff)
	add("git_branches", "List local branches with object IDs and upstreams.", "List git branches", gs.Branches)
	add("git_remotes", "List configured remote names and URLs without contacting them.", "List git remotes", gs.Remotes)
	mcp.AddTool(s, tool("git_log", "Show bounded structured commit history.", "Show git log", readOnly, &nonDestructive, true, &closed), func(ctx context.Context, _ *mcp.CallToolRequest, in logInput) (*mcp.CallToolResult, gitservice.Result, error) {
		out, err := gs.Log(ctx, in.MaxCount)
		return nil, out, err
	})
	mcp.AddTool(s, tool("git_show", "Show one validated revision with bounded patch and stat output.", "Show git revision", readOnly, &nonDestructive, true, &closed), func(ctx context.Context, _ *mcp.CallToolRequest, in showInput) (*mcp.CallToolResult, gitservice.Result, error) {
		out, err := gs.Show(ctx, in.Revision)
		return nil, out, err
	})
}

func registerGitWriteTools(s *mcp.Server, cfg config.Config, gs *gitservice.Service, closed bool) {
	destructive := true
	mcp.AddTool(s, tool("git_add", "Stage validated workspace paths.", "Stage git paths", false, &destructive, false, &closed), func(ctx context.Context, req *mcp.CallToolRequest, in pathsInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-write"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.Add(ctx, in.Paths)
		auditGit(req, "git_add", out, err, "client_id", toolOwner(cfg, req), "path_count", len(in.Paths))
		return nil, out, err
	})
	mcp.AddTool(s, tool("git_restore", "Restore validated workspace paths, optionally from the index.", "Restore git paths", false, &destructive, false, &closed), func(ctx context.Context, req *mcp.CallToolRequest, in restoreInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-write"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.Restore(ctx, in.Paths, in.Staged)
		auditGit(req, "git_restore", out, err, "client_id", toolOwner(cfg, req), "path_count", len(in.Paths), "staged", in.Staged)
		return nil, out, err
	})
	mcp.AddTool(s, tool("git_commit", "Create a commit with hooks disabled and a bounded message.", "Create git commit", false, &destructive, false, &closed), func(ctx context.Context, req *mcp.CallToolRequest, in messageInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-write"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.Commit(ctx, in.Message)
		auditGit(req, "git_commit", out, err, "client_id", toolOwner(cfg, req))
		return nil, out, err
	})
	mcp.AddTool(s, tool("git_branch", "Create one validated local branch.", "Create git branch", false, &destructive, false, &closed), func(ctx context.Context, req *mcp.CallToolRequest, in branchInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-write"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.CreateBranch(ctx, in.Name, in.StartPoint)
		auditGit(req, "git_branch", out, err, "client_id", toolOwner(cfg, req), "branch", in.Name, "start_point", in.StartPoint)
		return nil, out, err
	})
	mcp.AddTool(s, tool("git_switch", "Switch to one validated existing local branch.", "Switch git branch", false, &destructive, false, &closed), func(ctx context.Context, req *mcp.CallToolRequest, in switchInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-write"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.Switch(ctx, in.Branch)
		auditGit(req, "git_switch", out, err, "client_id", toolOwner(cfg, req), "branch", in.Branch)
		return nil, out, err
	})
	mcp.AddTool(s, tool("git_stash_push", "Create a stash with hooks and external helpers disabled.", "Push git stash", false, &destructive, false, &closed), func(ctx context.Context, req *mcp.CallToolRequest, in stashPushInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-write"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.StashPush(ctx, in.Message, in.IncludeUntracked)
		auditGit(req, "git_stash_push", out, err, "client_id", toolOwner(cfg, req), "include_untracked", in.IncludeUntracked)
		return nil, out, err
	})
	mcp.AddTool(s, tool("git_stash_pop", "Apply and drop one bounded stash entry.", "Pop git stash", false, &destructive, false, &closed), func(ctx context.Context, req *mcp.CallToolRequest, in stashPopInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-write"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.StashPop(ctx, in.Index)
		auditGit(req, "git_stash_pop", out, err, "client_id", toolOwner(cfg, req), "index", in.Index)
		return nil, out, err
	})
}

func registerGitNetworkTools(s *mcp.Server, cfg config.Config, gs *gitservice.Service, open bool) {
	destructive := true
	mcp.AddTool(s, tool("git_fetch", "Fetch from one configured allowed remote using isolated credentials.", "Fetch git remote", false, &destructive, false, &open), func(ctx context.Context, req *mcp.CallToolRequest, in remoteInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-network"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.Fetch(ctx, in.Remote)
		auditGit(req, "git_fetch", out, err, "client_id", toolOwner(cfg, req), "remote", in.Remote)
		return nil, out, err
	})
	mcp.AddTool(s, tool("git_pull", "Fast-forward-only pull from one configured allowed remote and branch.", "Pull git branch", false, &destructive, false, &open), func(ctx context.Context, req *mcp.CallToolRequest, in pullInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-network"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.Pull(ctx, in.Remote, in.Branch)
		auditGit(req, "git_pull", out, err, "client_id", toolOwner(cfg, req), "remote", in.Remote, "branch", in.Branch)
		return nil, out, err
	})
	mcp.AddTool(s, tool("git_push", "Push one validated refspec to one configured allowed remote using isolated credentials.", "Push git ref", false, &destructive, false, &open), func(ctx context.Context, req *mcp.CallToolRequest, in pushInput) (*mcp.CallToolResult, gitservice.Result, error) {
		if err := requireScope(cfg, req, "workspace:git-network"); err != nil {
			return nil, gitservice.Result{}, err
		}
		out, err := gs.Push(ctx, in.Remote, in.Refspec, in.ForceWithLease)
		auditGit(req, "git_push", out, err, "client_id", toolOwner(cfg, req), "remote", in.Remote, "refspec", in.Refspec, "force_with_lease", in.ForceWithLease)
		return nil, out, err
	})
}

func auditGit(req *mcp.CallToolRequest, toolName string, out gitservice.Result, err error, attrs ...any) {
	attrs = append(attrs, "exit_code", out.ExitCode, "stdout_truncated", out.StdoutTruncated, "stderr_truncated", out.StderrTruncated, "error", err != nil)
	auditTool(req, toolName, attrs...)
}

// auditWorkspace records a mutating workspace tool call. Callers pass paths and
// byte counts only, never file content, edit text or patch text.
func auditWorkspace(req *mcp.CallToolRequest, cfg config.Config, toolName string, err error, attrs ...any) {
	attrs = append([]any{"client_id", toolOwner(cfg, req)}, attrs...)
	attrs = append(attrs, "error", err != nil)
	auditTool(req, toolName, attrs...)
}

func auditTool(req *mcp.CallToolRequest, toolName string, attrs ...any) {
	base := []any{"tool", toolName}
	if req != nil && req.Extra != nil {
		if requestID := req.Extra.Header.Get("X-Request-ID"); requestID != "" {
			base = append(base, "request_id", requestID)
		}
	}
	slog.Info("dangerous MCP tool", append(base, attrs...)...)
}

func commandDigest(request sandboxexec.Request) string {
	h := sha256.New()
	if request.Script != "" {
		_, _ = h.Write([]byte("script\x00"))
		_, _ = h.Write([]byte(request.Script))
	} else {
		_, _ = h.Write([]byte("argv\x00"))
		for _, arg := range request.Argv {
			_, _ = h.Write([]byte(arg))
			_, _ = h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func tool(name, description, title string, readOnly bool, destructive *bool, idempotent bool, openWorld *bool) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{Title: title, ReadOnlyHint: readOnly, DestructiveHint: destructive, IdempotentHint: idempotent, OpenWorldHint: openWorld}}
}

func requireScope(cfg config.Config, req *mcp.CallToolRequest, scope string) error {
	if cfg.Mode == config.ModeLocal {
		return nil
	}
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil {
		return errors.New("missing authorization scope: " + scope)
	}
	for _, granted := range req.Extra.TokenInfo.Scopes {
		if granted == scope {
			return nil
		}
	}
	return errors.New("missing authorization scope: " + scope)
}

func toolOwner(cfg config.Config, req *mcp.CallToolRequest) string {
	if cfg.Mode == config.ModeLocal {
		return "local"
	}
	if req != nil && req.Extra != nil && req.Extra.TokenInfo != nil {
		if clientID, ok := req.Extra.TokenInfo.Extra["client_id"].(string); ok && clientID != "" {
			return clientID
		}
	}
	return "unauthorized"
}
