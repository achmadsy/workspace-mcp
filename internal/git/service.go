// Package git exposes two fixed, non-parameterized read-only Git operations.
package git

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/link/workspace-mcp/internal/limits"
	"github.com/link/workspace-mcp/internal/workspace"
)

type Service struct {
	root    *workspace.Root
	timeout time.Duration
}

type Result struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

func New(_ string, root *workspace.Root) *Service {
	return &Service{root: root, timeout: limits.GitTimeout}
}
func (s *Service) Status(ctx context.Context) (Result, error) { return s.run(ctx, "status", "--short") }
func (s *Service) Diff(ctx context.Context) (Result, error) {
	return s.run(ctx, "diff", "--no-ext-diff", "--no-textconv")
}

func (s *Service) run(parent context.Context, args ...string) (Result, error) {
	if !s.root.HasGitDir() {
		return Result{}, errors.New("workspace is not a Git repository")
	}
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	rootPath, cleanup, err := s.root.ProcPath()
	if err != nil {
		return Result{}, errors.New("workspace root is unavailable")
	}
	defer cleanup()
	base := []string{"-c", "core.pager=cat", "-c", "color.ui=false", "-c", "diff.external=", "-c", "diff.trustExitCode=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process="}
	cmd := exec.CommandContext(ctx, "git", append(base, args...)...)
	cmd.Dir = rootPath
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "GIT_PAGER=cat", "PAGER=cat", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C"}
	out := &limitBuffer{limit: limits.MaxGitOutput}
	er := &limitBuffer{limit: limits.MaxGitOutput}
	cmd.Stdout, cmd.Stderr = out, er
	err = cmd.Run()
	res := Result{Stdout: out.String(), Stderr: er.String(), StdoutTruncated: out.truncated, StderrTruncated: er.truncated}
	if err == nil {
		return res, nil
	}
	if ctx.Err() != nil {
		return Result{}, errors.New("git operation timed out")
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	return Result{}, errors.New("git executable could not be started")
}

type limitBuffer struct {
	b         bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remain := b.limit - b.b.Len()
	if remain > 0 {
		if len(p) > remain {
			p = p[:remain]
		}
		_, _ = b.b.Write(p)
	}
	if n > remain {
		b.truncated = true
	}
	return n, nil
}
func (b *limitBuffer) String() string { return b.b.String() }
