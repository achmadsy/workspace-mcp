package server

import (
	"context"

	gitservice "github.com/link/workspace-mcp/internal/git"
	"github.com/link/workspace-mcp/internal/limits"
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
type searchInput struct {
	Query      string `json:"query" jsonschema:"Literal case-sensitive text to find"`
	Path       string `json:"path,omitempty" jsonschema:"Relative file or directory; omit for workspace root"`
	MaxResults int    `json:"max_results,omitempty" jsonschema:"Maximum matches (1-200); default 50"`
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
type noInput struct{}

func registerTools(s *mcp.Server, ws *workspace.Root, gs *gitservice.Service) {
	readOnly := true
	closed := false
	destructive := true
	nonDestructive := false

	mcp.AddTool(s, &mcp.Tool{
		Name:        "workspace_list",
		Description: "List bounded workspace entries in deterministic lexical order. Symlinks and .git are never exposed.",
		Annotations: &mcp.ToolAnnotations{Title: "List workspace entries", ReadOnlyHint: readOnly, OpenWorldHint: &closed},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listInput) (*mcp.CallToolResult, workspace.ListResult, error) {
		out, err := ws.List(in.Path, in.Depth)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "workspace_read",
		Description: "Read one bounded UTF-8 regular file. Binary, symlinked, multiply-linked, oversized, and .git paths are rejected.",
		Annotations: &mcp.ToolAnnotations{Title: "Read workspace file", ReadOnlyHint: readOnly, OpenWorldHint: &closed},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in readInput) (*mcp.CallToolResult, workspace.ReadResult, error) {
		out, err := ws.Read(in.Path)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "workspace_search",
		Description: "Search literal case-sensitive text across bounded workspace files with deterministic results.",
		Annotations: &mcp.ToolAnnotations{Title: "Search workspace text", ReadOnlyHint: readOnly, OpenWorldHint: &closed},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, workspace.SearchResult, error) {
		ctx, cancel := context.WithTimeout(ctx, limits.ToolTimeout)
		defer cancel()
		out, err := ws.Search(ctx, in.Query, in.Path, in.MaxResults)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "workspace_write",
		Description: "Atomically create or replace one UTF-8 workspace file, creating safe parent directories.",
		Annotations: &mcp.ToolAnnotations{Title: "Write workspace file", DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closed},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in writeInput) (*mcp.CallToolResult, workspace.WriteResult, error) {
		out, err := ws.Write(in.Path, in.Content)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "workspace_edit",
		Description: "Atomically replace exactly one occurrence of old_text in one UTF-8 workspace file.",
		Annotations: &mcp.ToolAnnotations{Title: "Edit workspace file", DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closed},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in editInput) (*mcp.CallToolResult, workspace.EditResult, error) {
		out, err := ws.Edit(in.Path, in.OldText, in.NewText)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "git_status",
		Description: "Run fixed git status --short in the configured workspace repository. Accepts no arguments.",
		Annotations: &mcp.ToolAnnotations{Title: "Show git status", ReadOnlyHint: readOnly, DestructiveHint: &nonDestructive, IdempotentHint: true, OpenWorldHint: &closed},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, gitservice.Result, error) {
		out, err := gs.Status(ctx)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "git_diff",
		Description: "Run fixed git diff --no-ext-diff --no-textconv in the configured workspace repository. Accepts no arguments.",
		Annotations: &mcp.ToolAnnotations{Title: "Show git diff", ReadOnlyHint: readOnly, DestructiveHint: &nonDestructive, IdempotentHint: true, OpenWorldHint: &closed},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, gitservice.Result, error) {
		out, err := gs.Diff(ctx)
		return nil, out, err
	})
}
