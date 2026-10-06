package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePath(t *testing.T) {
	cases := []struct {
		name, in string
		ok       bool
	}{
		{"empty root", "", true},
		{"simple", "main.go", true},
		{"nested", "src/util.js", true},
		{"traversal", "../etc/passwd", false},
		{"deep traversal", "a/b/../../../etc/passwd", false},
		{"absolute", "/etc/passwd", false},
		{"tilde", "~/.ssh/id_rsa", false},
		{"dot", ".", false},
		{"dotdot", "..", false},
		{"empty component", "a//b", false},
		{"trailing slash", "src/", false},
		{"backslash", `a\b`, false},
		{"drive", "C:/x", false},
		{"nul", "a\x00b", false},
		{"git reserved", ".git/config", false},
		{"git direct", ".git", false},
		{"long component", string(make([]byte, 300)), false},
	}
	for _, tc := range cases {
		err := ValidatePath(tc.in, tc.in == "")
		if tc.ok != (err == nil) {
			t.Errorf("%s: ValidatePath(%q) = %v, want ok=%v", tc.name, tc.in, err, tc.ok)
		}
	}
}

func TestReadSymlinkEscape(t *testing.T) {
	r, dir := testRoot(t)
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read("out"); err == nil {
		t.Fatal("read through outbound symlink must fail")
	}
}

func TestReadInternalSymlinkDenied(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "real.txt", "content")
	if err := os.Symlink("real.txt", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read("alias"); err == nil {
		t.Fatal("read through internal symlink must fail (deny-all policy)")
	}
}

func TestReadHardLinkDenied(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "a.txt", "data")
	external := filepath.Join(t.TempDir(), "ext")
	if err := os.WriteFile(external, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(external, filepath.Join(dir, "hard")); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	if _, err := r.Read("hard"); err == nil {
		t.Fatal("read of multiply-linked file must fail")
	}
}

func TestWriteAtomicReplace(t *testing.T) {
	r, dir := testRoot(t)
	w1, err := r.Write("d/f.txt", "one")
	if err != nil || !w1.Changed {
		t.Fatalf("first write: %v %+v", err, w1)
	}
	w2, err := r.Write("d/f.txt", "one")
	if err != nil || w2.Changed {
		t.Fatalf("idempotent write: %v %+v", err, w2)
	}
	got, err := r.Read("d/f.txt")
	if err != nil || got.Content != "one" {
		t.Fatalf("read back: %v %+v", err, got)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "d")); err != nil || len(entries) != 1 {
		t.Fatalf("temporary files leaked: %v %d", err, len(entries))
	}
	if err := os.Symlink("/tmp", filepath.Join(dir, "d", "link")); err == nil {
		if _, err := r.Write("d/link/x.txt", "no"); err == nil {
			t.Fatal("write through symlink parent must fail")
		}
	}
}

func TestEditOccurrences(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "e.txt", "alpha beta alpha")
	if _, err := r.Edit("e.txt", "alpha", "X"); err == nil {
		t.Fatal("multiple occurrences must fail")
	}
	if _, err := r.Edit("e.txt", "missing", "X"); err == nil {
		t.Fatal("missing old_text must fail")
	}
	if _, err := r.Edit("e.txt", "", "X"); err == nil {
		t.Fatal("empty old_text must fail")
	}
	got, _ := r.Read("e.txt")
	if got.Content != "alpha beta alpha" {
		t.Fatal("failed edits must not mutate")
	}
	mustWrite(t, dir, "one.txt", "alpha beta")
	res, err := r.Edit("one.txt", "beta", "gamma")
	if err != nil || !res.Changed {
		t.Fatalf("single edit: %v %+v", err, res)
	}
	got, _ = r.Read("one.txt")
	if got.Content != "alpha gamma" {
		t.Fatalf("edit result: %q", got.Content)
	}
}

func TestSearchBoundsAndIgnores(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "a.txt", "find me\nsecond line\n")
	mustWrite(t, dir, "node_modules/x.txt", "find me")
	mustWrite(t, dir, "sub/b.txt", "no match here\nfind me too\n")
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err == nil {
		mustWrite(t, dir, ".git/hidden.txt", "find me")
	}
	res, err := r.Search(t.Context(), "find me", "", 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Matches) != 2 {
		t.Fatalf("expected 2 matches, got %+v", res.Matches)
	}
	if res.Matches[0].RelativePath != "a.txt" || res.Matches[1].RelativePath != "sub/b.txt" {
		t.Fatalf("deterministic order violated: %+v", res.Matches)
	}
	if _, err := r.Search(t.Context(), "", "", 10); !errors.Is(err, errSearchQuery) && err == nil {
		t.Fatal("empty query must fail")
	}
}

var errSearchQuery = errors.New("query must not be empty")

func TestListDepthAndIgnore(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "vendor/lib/x.txt", "x")
	mustWrite(t, dir, "deep/a/b/c.txt", "c")
	res, err := r.List("", 2)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, e := range res.Entries {
		paths[e.Path] = true
	}
	if paths["vendor/lib/x.txt"] {
		t.Fatal("ignored directory leaked")
	}
	if !paths["deep/a"] {
		t.Fatal("expected nested entry")
	}
	if paths["deep/a/b/c.txt"] {
		t.Fatal("depth exceeded")
	}
}
