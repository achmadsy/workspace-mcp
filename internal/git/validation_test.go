package git

import (
	"strings"
	"testing"
)

func TestValidatePaths(t *testing.T) {
	t.Parallel()
	if err := validatePaths([]string{"src/main.go", "README.md"}); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][]string{nil, {"--all"}, {"../escape"}, {".git/config"}} {
		if err := validatePaths(paths); err == nil {
			t.Fatalf("unsafe paths accepted: %#v", paths)
		}
	}
}

func TestValidateBranchesRevisionsAndRefspecs(t *testing.T) {
	t.Parallel()
	for _, branch := range []string{"main", "feature/typed-git", "release-1.0"} {
		if err := validateBranch(branch); err != nil {
			t.Errorf("valid branch %q: %v", branch, err)
		}
	}
	for _, branch := range []string{"", "-f", "../main", "a..b", "a.lock", "a@{1}"} {
		if err := validateBranch(branch); err == nil {
			t.Errorf("invalid branch accepted: %q", branch)
		}
	}
	for _, revision := range []string{"HEAD", "main", "abc123"} {
		if err := validateRevision(revision); err != nil {
			t.Errorf("valid revision %q: %v", revision, err)
		}
	}
	for _, revision := range []string{"HEAD~1", "main^", "-p", "@{upstream}"} {
		if err := validateRevision(revision); err == nil {
			t.Errorf("unsafe revision accepted: %q", revision)
		}
	}
	for _, refspec := range []string{"main", "main:refs/heads/main", "HEAD:refs/heads/topic"} {
		if err := validateRefspec(refspec); err != nil {
			t.Errorf("valid refspec %q: %v", refspec, err)
		}
	}
	for _, refspec := range []string{"", "--all", ":main", "main:", "a:b:c", "main^:x"} {
		if err := validateRefspec(refspec); err == nil {
			t.Errorf("unsafe refspec accepted: %q", refspec)
		}
	}
}

func TestValidateRemoteURL(t *testing.T) {
	t.Parallel()
	for _, remote := range []string{"https://github.com/example/repo.git", "ssh://git@example.com/repo.git", "git@example.com:repo.git"} {
		if err := ValidateRemoteURL(remote); err != nil {
			t.Errorf("valid remote %q: %v", remote, err)
		}
	}
	for _, remote := range []string{
		"http://example.com/repo.git", "file:///tmp/repo", "https://token@example.com/repo.git",
		"ext::sh -c evil", "https://example.com/repo.git?token=x", "git@example.com:repo.git\nmalicious",
	} {
		if err := ValidateRemoteURL(remote); err == nil {
			t.Errorf("unsafe remote accepted: %q", remote)
		}
	}
}

func TestDangerousOperationsDisabledWithoutRunner(t *testing.T) {
	s, _, _ := setupRepo(t)
	if _, err := s.Add(t.Context(), []string{"f.txt"}); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("Add without runner error = %v", err)
	}
	if _, err := s.Push(t.Context(), "origin", "main", false); err == nil {
		t.Fatal("Push without runner succeeded")
	}
}

func TestReadOperations(t *testing.T) {
	s, _, _ := setupRepo(t)
	logResult, err := s.Log(t.Context(), 5)
	if err != nil || logResult.ExitCode != 0 || !strings.Contains(logResult.Stdout, "init") {
		t.Fatalf("log = %#v, %v", logResult, err)
	}
	show, err := s.Show(t.Context(), "HEAD")
	if err != nil || show.ExitCode != 0 || !strings.Contains(show.Stdout, "commit") {
		t.Fatalf("show = %#v, %v", show, err)
	}
	branches, err := s.Branches(t.Context())
	if err != nil || branches.ExitCode != 0 || strings.TrimSpace(branches.Stdout) == "" {
		t.Fatalf("branches = %#v, %v", branches, err)
	}
	remotes, err := s.Remotes(t.Context())
	if err != nil || remotes.ExitCode != 0 {
		t.Fatalf("remotes = %#v, %v", remotes, err)
	}
}

func TestInputValidationErrors(t *testing.T) {
	s, _, _ := setupRepo(t)

	// Log count bounds.
	if _, err := s.Log(t.Context(), -1); err == nil {
		t.Fatal("negative log count accepted")
	}
	if _, err := s.Log(t.Context(), 201); err == nil {
		t.Fatal("log count > 200 accepted")
	}
	// Log count 0 defaults to 20.
	if res, err := s.Log(t.Context(), 0); err != nil || res.ExitCode != 0 {
		t.Fatalf("log count 0 failed: %v", err)
	}

	// Show invalid revision.
	if _, err := s.Show(t.Context(), "-p"); err == nil {
		t.Fatal("show flag accepted as revision")
	}

	// Commit message validation.
	if _, err := s.Commit(t.Context(), ""); err == nil {
		t.Fatal("empty commit message accepted")
	}
	if _, err := s.Commit(t.Context(), "has\x00nul"); err == nil {
		t.Fatal("commit message with NUL accepted")
	}
	if _, err := s.Commit(t.Context(), strings.Repeat("x", 70000)); err == nil {
		t.Fatal("oversized commit message accepted")
	}

	// Branch validation.
	if _, err := s.CreateBranch(t.Context(), "-bad", ""); err == nil {
		t.Fatal("invalid branch name accepted")
	}
	if _, err := s.CreateBranch(t.Context(), "good-name", "-bad-start"); err == nil {
		t.Fatal("invalid start point accepted")
	}
	if _, err := s.Switch(t.Context(), "-bad"); err == nil {
		t.Fatal("invalid switch branch accepted")
	}

	// Stash validation.
	if _, err := s.StashPush(t.Context(), "has\x00nul", false); err == nil {
		t.Fatal("stash message with NUL accepted")
	}
	if _, err := s.StashPop(t.Context(), -1); err == nil {
		t.Fatal("negative stash index accepted")
	}
	if _, err := s.StashPop(t.Context(), 1001); err == nil {
		t.Fatal("stash index > 1000 accepted")
	}

	// Add and Restore validation.
	if _, err := s.Add(t.Context(), []string{"-flag"}); err == nil {
		t.Fatal("add flag accepted as path")
	}
	if _, err := s.Restore(t.Context(), []string{"-flag"}, false); err == nil {
		t.Fatal("restore flag accepted as path")
	}

	// Network remote validation.
	if _, err := s.Fetch(t.Context(), "unconfigured"); err == nil {
		t.Fatal("unconfigured remote accepted for fetch")
	}
	if _, err := s.Pull(t.Context(), "unconfigured", "main"); err == nil {
		t.Fatal("unconfigured remote accepted for pull")
	}
	if _, err := s.Push(t.Context(), "unconfigured", "main", false); err == nil {
		t.Fatal("unconfigured remote accepted for push")
	}
	if _, err := s.Fetch(t.Context(), "-flag"); err == nil {
		t.Fatal("flag accepted as remote name")
	}
	if _, err := s.Pull(t.Context(), "", "main"); err == nil {
		t.Fatal("empty remote name accepted")
	}
	if _, err := s.Push(t.Context(), "", "main", false); err == nil {
		t.Fatal("empty remote name accepted")
	}
}

func TestLimitBuffer(t *testing.T) {
	buf := &limitBuffer{limit: 10}
	n, err := buf.Write([]byte("hello"))
	if err != nil || n != 5 || buf.truncated || buf.String() != "hello" {
		t.Fatalf("unexpected buffer state: %d, %v, %v, %q", n, err, buf.truncated, buf.String())
	}
	n, err = buf.Write([]byte("world-overflow"))
	if err != nil || n != 14 || !buf.truncated || buf.String() != "helloworld" {
		t.Fatalf("unexpected truncated buffer state: %d, %v, %v, %q", n, err, buf.truncated, buf.String())
	}
}

func TestEnvironmentSlice(t *testing.T) {
	env := map[string]string{
		"B": "2",
		"A": "1",
	}
	slice := environmentSlice(env)
	if len(slice) != 3 {
		t.Fatalf("slice length %d, want 3", len(slice))
	}
	if slice[0] != "PATH=/usr/bin:/bin" {
		t.Fatalf("slice[0] = %q", slice[0])
	}
	if slice[1] != "A=1" || slice[2] != "B=2" {
		t.Fatalf("slice not sorted: %v", slice)
	}
}
