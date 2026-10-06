package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func testRoot(t *testing.T) (*Root, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r, dir
}

func mustWrite(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestListBasic(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "README.md", "hello")
	mustWrite(t, dir, "src/util.js", "x")
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Skipf("git unavailable: %v %s", err, out)
	}
	res, err := r.List("", 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Entries) == 0 {
		t.Fatal("expected entries, got none")
	}
	for _, e := range res.Entries {
		if e.Path == ".git" || filepath.Base(e.Path) == ".git" {
			t.Fatalf(".git leaked: %+v", e)
		}
	}
}

func TestListWithSymlinksAndBinary(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "README.md", "hello")
	mustWrite(t, dir, "binary.bin", "bin\x00ary")
	mustWrite(t, dir, "notes/x.md", "note")
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "escape_link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("README.md", filepath.Join(dir, "internal_link")); err != nil {
		t.Fatal(err)
	}
	res, err := r.List("", 1)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	t.Logf("entries=%+v truncated=%v", res.Entries, res.Truncated)
	if len(res.Entries) != 3 {
		t.Fatalf("expected 3 entries (README.md, binary.bin, notes), got %d: %+v", len(res.Entries), res.Entries)
	}
}

func TestListExactFixture(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "README.md", "hello")
	mustWrite(t, dir, "main.go", "package main")
	mustWrite(t, dir, "binary.bin", "bin\x00ary")
	mustWrite(t, dir, "notes/acceptance.md", "note")
	mustWrite(t, dir, "src/util.js", "x")
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "escape_link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("main.go", filepath.Join(dir, "internal_link")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../..", filepath.Join(dir, "sub", "parent_escape")); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Skipf("git: %v %s", err, out)
	}
	res, err := r.List("", 1)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	t.Logf("entries=%d %+v", len(res.Entries), res.Entries)
}
