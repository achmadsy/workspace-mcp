// Package git exposes bounded, typed Git operations.
package git

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/limits"
	"github.com/link/workspace-mcp/internal/sandboxexec"
	"github.com/link/workspace-mcp/internal/workspace"
)

type Service struct {
	root        *workspace.Root
	timeout     time.Duration
	runner      *sandboxexec.Runner
	cfg         sandboxexecConfig
	credentials *credentialBroker
}

type sandboxexecConfig struct {
	gitWrite   bool
	gitNetwork bool
	remotes    map[string]struct{}
}

type Result struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

// New preserves safe-profile construction for existing callers and tests.
func New(_ string, root *workspace.Root) *Service {
	return &Service{root: root, timeout: limits.GitTimeout}
}

// NewAgentic configures typed Git writes/network access and opens credential
// descriptors at startup so later path replacement cannot redirect reads.
func NewAgentic(root *workspace.Root, runner *sandboxexec.Runner) (*Service, error) {
	if runner == nil {
		return New("", root), nil
	}
	cfg := runner.Config()
	broker, err := newCredentialBroker(cfg)
	if err != nil {
		return nil, err
	}
	s := &Service{
		root: root, timeout: limits.GitTimeout, runner: runner, credentials: broker,
		cfg: sandboxexecConfig{
			gitWrite: cfg.EnableGitWrite, gitNetwork: cfg.EnableGitNetwork,
			remotes: make(map[string]struct{}, len(cfg.GitAllowedRemotes)),
		},
	}
	for _, remote := range cfg.GitAllowedRemotes {
		s.cfg.remotes[remote] = struct{}{}
	}
	return s, nil
}

func (s *Service) Close() {
	if s != nil {
		s.credentials.close()
	}
}

func (s *Service) Status(ctx context.Context) (Result, error) {
	return s.runRead(ctx, "status", "--short")
}

func (s *Service) Diff(ctx context.Context) (Result, error) {
	return s.runRead(ctx, "diff", "--no-ext-diff", "--no-textconv")
}

func (s *Service) Log(ctx context.Context, maxCount int) (Result, error) {
	if maxCount == 0 {
		maxCount = 20
	}
	if maxCount < 1 || maxCount > 200 {
		return Result{}, errors.New("max_count is outside allowed range")
	}
	return s.runRead(ctx, "log", "--no-decorate", "--date=iso-strict", "--format=%H%x09%aI%x09%an%x09%s", "-n", strconv.Itoa(maxCount))
}

func (s *Service) Show(ctx context.Context, revision string) (Result, error) {
	if err := validateRevision(revision); err != nil {
		return Result{}, err
	}
	return s.runRead(ctx, "show", "--no-ext-diff", "--no-textconv", "--format=fuller", "--stat", "--end-of-options", revision, "--")
}

func (s *Service) Branches(ctx context.Context) (Result, error) {
	return s.runRead(ctx, "branch", "--list", "--no-color", "--format=%(refname:short)%09%(objectname)%09%(upstream:short)")
}

func (s *Service) Remotes(ctx context.Context) (Result, error) {
	return s.runRead(ctx, "remote", "-v")
}

func (s *Service) Add(ctx context.Context, paths []string) (Result, error) {
	if err := validatePaths(paths); err != nil {
		return Result{}, err
	}
	return s.runWrite(ctx, append([]string{"add", "--"}, paths...)...)
}

func (s *Service) Restore(ctx context.Context, paths []string, staged bool) (Result, error) {
	if err := validatePaths(paths); err != nil {
		return Result{}, err
	}
	args := []string{"restore"}
	if staged {
		args = append(args, "--staged")
	}
	args = append(args, "--")
	args = append(args, paths...)
	return s.runWrite(ctx, args...)
}

func (s *Service) Commit(ctx context.Context, message string) (Result, error) {
	if message == "" || len(message) > limits.MaxGitCommitMessageBytes || !utf8.ValidString(message) || strings.IndexByte(message, 0) >= 0 {
		return Result{}, errors.New("commit message is empty, invalid, or exceeds limit")
	}
	return s.runWrite(ctx, "commit", "--no-verify", "-m", message, "--")
}

func (s *Service) CreateBranch(ctx context.Context, name, startPoint string) (Result, error) {
	if err := validateBranch(name); err != nil {
		return Result{}, err
	}
	args := []string{"branch", "--", name}
	if startPoint != "" {
		if err := validateRevision(startPoint); err != nil {
			return Result{}, err
		}
		args = []string{"branch", "--", name, startPoint}
	}
	return s.runWrite(ctx, args...)
}

func (s *Service) Switch(ctx context.Context, branch string) (Result, error) {
	if err := validateBranch(branch); err != nil {
		return Result{}, err
	}
	return s.runWrite(ctx, "switch", "--", branch)
}

func (s *Service) StashPush(ctx context.Context, message string, includeUntracked bool) (Result, error) {
	if len(message) > limits.MaxGitCommitMessageBytes || !utf8.ValidString(message) || strings.IndexByte(message, 0) >= 0 {
		return Result{}, errors.New("stash message is invalid or exceeds limit")
	}
	args := []string{"stash", "push", "--no-keep-index"}
	if includeUntracked {
		args = append(args, "--include-untracked")
	}
	if message != "" {
		args = append(args, "-m", message)
	}
	args = append(args, "--")
	return s.runWrite(ctx, args...)
}

func (s *Service) StashPop(ctx context.Context, index int) (Result, error) {
	if index < 0 || index > 1000 {
		return Result{}, errors.New("stash index is outside allowed range")
	}
	return s.runWrite(ctx, "stash", "pop", "--index", "stash@{"+strconv.Itoa(index)+"}")
}

func (s *Service) Fetch(ctx context.Context, remote string) (Result, error) {
	remoteURL, err := s.resolveRemoteURL(ctx, remote)
	if err != nil {
		return Result{}, err
	}
	return s.runNetwork(ctx, remoteURL, "fetch", "--no-tags", "--prune", "--", remoteURL)
}

func (s *Service) Pull(ctx context.Context, remote, branch string) (Result, error) {
	remoteURL, err := s.resolveRemoteURL(ctx, remote)
	if err != nil {
		return Result{}, err
	}
	if err := validateBranch(branch); err != nil {
		return Result{}, err
	}
	return s.runNetwork(ctx, remoteURL, "pull", "--ff-only", "--no-tags", "--", remoteURL, branch)
}

func (s *Service) Push(ctx context.Context, remote, refspec string, forceWithLease bool) (Result, error) {
	remoteURL, err := s.resolveRemoteURL(ctx, remote)
	if err != nil {
		return Result{}, err
	}
	if err := validateRefspec(refspec); err != nil {
		return Result{}, err
	}
	args := []string{"push", "--porcelain"}
	if forceWithLease {
		args = append(args, "--force-with-lease")
	}
	args = append(args, "--", remoteURL, refspec)
	return s.runNetwork(ctx, remoteURL, args...)
}

func (s *Service) runRead(ctx context.Context, args ...string) (Result, error) {
	if s.runner != nil {
		return s.runSandbox(ctx, false, args...)
	}
	return s.runHost(ctx, args...)
}

func (s *Service) runWrite(ctx context.Context, args ...string) (Result, error) {
	if s.runner == nil || !s.cfg.gitWrite {
		return Result{}, errors.New("Git write operations are disabled")
	}
	return s.runSandbox(ctx, false, args...)
}

func (s *Service) runNetwork(ctx context.Context, remoteURL string, args ...string) (Result, error) {
	if s.runner == nil || !s.cfg.gitNetwork {
		return Result{}, errors.New("Git network operations are disabled")
	}
	credentials, cleanup, err := s.credentials.filesForURL(remoteURL)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()
	return s.runSandboxWithCredentials(ctx, args, credentials, true)
}

func (s *Service) runSandbox(parent context.Context, network bool, args ...string) (Result, error) {
	if network {
		return Result{}, errors.New("credential-aware Git network path is required")
	}
	return s.runSandboxWithCredentials(parent, args, sandboxexec.GitCredentialFiles{}, false)
}

func (s *Service) runSandboxWithCredentials(parent context.Context, args []string, credentials sandboxexec.GitCredentialFiles, network bool) (Result, error) {
	if !s.root.HasGitDir() {
		return Result{}, errors.New("workspace is not a Git repository")
	}
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	request := sandboxexec.Request{Argv: append([]string{"/usr/bin/git"}, append(gitBaseArgs(), args...)...), TimeoutMS: int(s.timeout / time.Millisecond)}
	extraEnv := gitEnvironment()
	var result sandboxexec.Result
	var err error
	if network {
		result, err = s.runner.RunGitNetwork(ctx, request, extraEnv, credentials)
	} else {
		result, err = s.runner.RunIsolated(ctx, request, extraEnv)
	}
	if err != nil {
		return Result{}, err
	}
	return Result{
		Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode,
		StdoutTruncated: result.StdoutTruncated, StderrTruncated: result.StderrTruncated,
	}, nil
}

func (s *Service) runHost(parent context.Context, args ...string) (Result, error) {
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
	cmd := exec.CommandContext(ctx, "git", append(gitBaseArgs(), args...)...)
	cmd.Dir = rootPath
	cmd.Env = environmentSlice(gitEnvironment())
	out := &limitBuffer{limit: limits.MaxGitOutput}
	errOut := &limitBuffer{limit: limits.MaxGitOutput}
	cmd.Stdout, cmd.Stderr = out, errOut
	err = cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errOut.String(), StdoutTruncated: out.truncated, StderrTruncated: errOut.truncated}
	if err == nil {
		return res, nil
	}
	if ctx.Err() != nil {
		return Result{}, errors.New("git operation timed out")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return Result{}, errors.New("git executable could not be started")
}

func gitBaseArgs() []string {
	return []string{
		"-c", "core.pager=cat", "-c", "color.ui=false", "-c", "diff.external=",
		"-c", "diff.trustExitCode=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=",
		"-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=never", "-c", "protocol.allow=never", "-c", "protocol.http.allow=always",
		"-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
	}
}

func gitEnvironment() map[string]string {
	return map[string]string{
		"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
		"GIT_ASKPASS": "/bin/false", "GIT_PAGER": "cat", "PAGER": "cat", "GIT_OPTIONAL_LOCKS": "0",
		"LC_ALL": "C", "LANG": "C", "HOME": "/home",
	}
}

func environmentSlice(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(values)+1)
	out = append(out, "PATH=/usr/bin:/bin")
	for _, key := range keys {
		out = append(out, key+"="+values[key])
	}
	return out
}

func validatePaths(paths []string) error {
	if len(paths) == 0 || len(paths) > limits.MaxGitPaths {
		return errors.New("paths count is outside allowed range")
	}
	for _, path := range paths {
		if strings.HasPrefix(path, "-") {
			return errors.New("path must not begin with an option prefix")
		}
		if err := workspace.ValidatePath(path, false); err != nil {
			return err
		}
	}
	return nil
}

var refComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

func validateBranch(branch string) error {
	if len(branch) == 0 || len(branch) > 255 || strings.HasPrefix(branch, "-") || !refComponent.MatchString(branch) ||
		strings.Contains(branch, "..") || strings.Contains(branch, "//") || strings.Contains(branch, "@{") ||
		strings.HasSuffix(branch, ".") || strings.HasSuffix(branch, "/") || strings.HasSuffix(branch, ".lock") {
		return errors.New("invalid branch name")
	}
	return nil
}

func validateRevision(revision string) error {
	if revision == "HEAD" {
		return nil
	}
	if strings.HasPrefix(revision, "-") || strings.ContainsAny(revision, "~^:{}?*[\\ ") {
		return errors.New("invalid revision")
	}
	return validateBranch(revision)
}

func validateRefspec(refspec string) error {
	if refspec == "" || len(refspec) > 512 || strings.HasPrefix(refspec, "-") || strings.Count(refspec, ":") > 1 {
		return errors.New("invalid refspec")
	}
	parts := strings.Split(refspec, ":")
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "~^{}?*[\\ ") || strings.Contains(part, "..") || strings.Contains(part, "@{") {
			return errors.New("invalid refspec")
		}
	}
	return nil
}

func (s *Service) validateRemote(remote string) error {
	if _, ok := s.cfg.remotes[remote]; !ok || remote == "" || strings.HasPrefix(remote, "-") {
		return errors.New("remote is not allowed")
	}
	return nil
}

func (s *Service) resolveRemoteURL(ctx context.Context, remote string) (string, error) {
	if err := s.validateRemote(remote); err != nil {
		return "", err
	}
	if err := s.auditNetworkConfig(ctx); err != nil {
		return "", err
	}
	result, err := s.runSandbox(ctx, false, "remote", "get-url", "--", remote)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 || result.StdoutTruncated {
		return "", errors.New("remote URL could not be resolved")
	}
	raw := strings.TrimSpace(result.Stdout)
	if strings.Contains(raw, "\n") || ValidateRemoteURL(raw) != nil {
		return "", errors.New("remote URL is invalid or unsupported")
	}
	return raw, nil
}

func (s *Service) auditNetworkConfig(ctx context.Context) error {
	result, err := s.runSandbox(ctx, false, "config", "--local", "--name-only", "--get-regexp", `^(url\..*\.(insteadof|pushinsteadof)|credential($|\..*)|http($|\..*)|core\.sshcommand|ssh\.variant|remote\..*\.(vcs|proxy))$`)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 && result.ExitCode != 1 {
		return errors.New("repository Git network configuration could not be audited")
	}
	if strings.TrimSpace(result.Stdout) != "" {
		return errors.New("repository contains forbidden Git network configuration")
	}
	return nil
}

func ValidateRemoteURL(raw string) error {
	if strings.HasPrefix(raw, "git@") {
		if strings.ContainsAny(raw, "\r\n\x00 ") || !strings.Contains(raw, ":") || strings.HasSuffix(raw, ":") {
			return errors.New("invalid SSH remote URL")
		}
		return nil
	}
	if strings.HasPrefix(raw, "ssh://") {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "ssh" || u.Host == "" || u.Path == "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\x00 ") {
			return errors.New("invalid SSH remote URL")
		}
		if u.User != nil && u.User.Username() != "git" {
			return errors.New("SSH remote user must be git")
		}
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("remote URL must be HTTPS or SSH without embedded credentials")
	}
	return nil
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
