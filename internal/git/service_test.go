package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/link/workspace-mcp/internal/workspace"
)

func setupRepo(t *testing.T) (*Service, *workspace.Root, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	dir := t.TempDir()
	r, err := workspace.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	s := New(dir, r)
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Skipf("git init: %v %s", err, out)
	}
	env := append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	for _, args := range [][]string{{"config", "user.email", "t@t"}, {"config", "user.name", "t"}} {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := c.CombinedOutput(); err != nil {
			t.Skipf("git config: %v %s", err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", dir, "add", "-A")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git add: %v %s", err, out)
	}
	cmd = exec.Command("git", "-C", dir, "commit", "-qm", "init")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git commit: %v %s", err, out)
	}
	return s, r, dir
}

func TestStatusAndDiff(t *testing.T) {
	s, _, dir := setupRepo(t)
	st, err := s.Status(t.Context())
	if err != nil || st.ExitCode != 0 || st.Stdout != "" {
		t.Fatalf("clean status: %v %+v", err, st)
	}
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err = s.Status(t.Context())
	if err != nil || st.ExitCode != 0 || len(st.Stdout) == 0 {
		t.Fatalf("dirty status: %v %+v", err, st)
	}
	d, err := s.Diff(t.Context())
	if err != nil || d.ExitCode != 0 || !contains(d.Stdout, "+changed") {
		t.Fatalf("diff: %v %+v", err, d)
	}
}

func TestNonRepository(t *testing.T) {
	dir := t.TempDir()
	r, err := workspace.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s := New(dir, r)
	if _, err := s.Status(t.Context()); err == nil {
		t.Fatal("non-repository must fail")
	}
}

func TestNewAgenticNilRunner(t *testing.T) {
	dir := t.TempDir()
	r, err := workspace.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s, err := NewAgentic(r, nil)
	if err != nil {
		t.Fatalf("NewAgentic with nil runner: %v", err)
	}
	defer s.Close()
	if s.runner != nil {
		t.Fatal("expected nil runner")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
