//go:build linux

package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStatReadRangeAndGlob(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "src/a.go", "alpha\nbeta\n")
	mustWrite(t, dir, "src/b.txt", "other")
	mustWrite(t, dir, "src/nested/c.go", "gamma")
	if err := os.Symlink("a.go", filepath.Join(dir, "src", "alias.go")); err != nil {
		t.Fatal(err)
	}

	stat, err := r.Stat("src/a.go")
	if err != nil || stat.Type != "file" || stat.Size != 11 || stat.ModTime == "" {
		t.Fatalf("stat = %#v, %v", stat, err)
	}
	link, err := r.Stat("src/alias.go")
	if err != nil || link.Type != "symlink" {
		t.Fatalf("symlink stat = %#v, %v", link, err)
	}
	rangeResult, err := r.ReadRange("src/a.go", 6, 4)
	if err != nil || rangeResult.Content != "beta" || rangeResult.NextOffset != 10 || rangeResult.Size != 11 {
		t.Fatalf("range = %#v, %v", rangeResult, err)
	}
	matches, err := r.Glob("*/*.go", "src")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"src/nested/c.go"}; !reflect.DeepEqual(matches.Paths, want) || matches.Truncated {
		t.Fatalf("matches = %#v, want %#v", matches, want)
	}
	matches, err = r.Glob("*.go", "src")
	if err != nil || !reflect.DeepEqual(matches.Paths, []string{"src/a.go"}) || matches.Truncated {
		t.Fatalf("flat matches = %#v, %v", matches, err)
	}
	none, err := r.Glob("*.rs", "src")
	if err != nil || none.Paths == nil || len(none.Paths) != 0 || none.Truncated {
		t.Fatalf("empty glob must give an empty, non-nil list: %#v, %v", none, err)
	}
}

func TestGlobTruncatesInsteadOfFailing(t *testing.T) {
	r, dir := testRoot(t)
	for i := 0; i < 2001; i++ {
		mustWrite(t, dir, fmt.Sprintf("many/f%04d.txt", i), "x")
	}
	res, err := r.Glob("*.txt", "many")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || res.TruncatedReason == "" || len(res.Paths) != 2000 {
		t.Fatalf("glob = %d paths truncated=%t reason=%q", len(res.Paths), res.Truncated, res.TruncatedReason)
	}
	if res.Paths[0] != "many/f0000.txt" || res.Paths[1999] != "many/f1999.txt" {
		t.Fatalf("partial result is not the sorted prefix: %q ... %q", res.Paths[0], res.Paths[1999])
	}
}

func TestSearchOptions(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "src/a.go", "before\nNeedle here\nafter\n")
	mustWrite(t, dir, "src/b.txt", "needle here\n")
	res, err := r.SearchWithOptions(t.Context(), "needle", SearchOptions{
		Path: "src", MaxResults: 10, CaseInsensitive: true, Include: []string{"*.go"}, ContextLines: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 || res.Matches[0].RelativePath != "src/a.go" ||
		!reflect.DeepEqual(res.Matches[0].Before, []string{"before"}) ||
		!reflect.DeepEqual(res.Matches[0].After, []string{"after"}) {
		t.Fatalf("search result = %#v", res)
	}
}

func TestMkdirCopyMoveDelete(t *testing.T) {
	r, dir := testRoot(t)
	mkdir, err := r.Mkdir("a/b", true)
	if err != nil || !mkdir.Changed {
		t.Fatalf("mkdir = %#v, %v", mkdir, err)
	}
	mustWrite(t, dir, "source.txt", "content")
	copyResult, err := r.Copy("source.txt", "a/b/copy.txt", false)
	if err != nil || !copyResult.Changed {
		t.Fatalf("copy = %#v, %v", copyResult, err)
	}
	if _, err := r.Copy("source.txt", "a/b/copy.txt", false); err == nil {
		t.Fatal("copy without overwrite replaced destination")
	}
	moveResult, err := r.Move("a/b/copy.txt", "a/b/moved.txt", false)
	if err != nil || !moveResult.Changed {
		t.Fatalf("move = %#v, %v", moveResult, err)
	}
	if _, err := r.Read("a/b/copy.txt"); err == nil {
		t.Fatal("move retained source")
	}
	if _, err := r.Delete("a", false); err == nil {
		t.Fatal("directory delete without recursive accepted")
	}
	deleted, err := r.Delete("a", true)
	if err != nil || !deleted.Changed {
		t.Fatalf("delete = %#v, %v", deleted, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
		t.Fatalf("deleted tree remains: %v", err)
	}
}

func TestMutationsRejectSymlinksAndHardLinks(t *testing.T) {
	r, dir := testRoot(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Delete("link", false); err == nil {
		t.Fatal("delete accepted symlink")
	}
	if _, err := r.Move("link", "moved", false); err == nil {
		t.Fatal("move accepted symlink")
	}
	if _, err := r.Copy("link", "copy", false); err == nil {
		t.Fatal("copy accepted symlink")
	}
	if err := os.Link(outside, filepath.Join(dir, "hard")); err == nil {
		if _, err := r.Delete("hard", false); err == nil {
			t.Fatal("delete accepted multiply-linked file")
		}
		if _, err := r.Copy("hard", "copy-hard", false); err == nil {
			t.Fatal("copy accepted multiply-linked file")
		}
	}
}

func TestApplyPatchPrevalidatesAllFiles(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "a.txt", "one\ntwo\n")
	mustWrite(t, dir, "b.txt", "three\nfour\n")
	patch := "--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+second\n" +
		"--- a/b.txt\n+++ b/b.txt\n@@ -1,2 +1,2 @@\n mismatch\n-four\n+fourth\n"
	if _, err := r.ApplyPatch(patch); err == nil {
		t.Fatal("invalid second file patch accepted")
	}
	got, _ := r.Read("a.txt")
	if got.Content != "one\ntwo\n" {
		t.Fatalf("prevalidation failure partially mutated first file: %q", got.Content)
	}

	patch = "--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+second\n" +
		"--- a/b.txt\n+++ b/b.txt\n@@ -1,2 +1,2 @@\n three\n-four\n+fourth\n"
	result, err := r.ApplyPatch(patch)
	if err != nil || result.FilesChanged != 2 {
		t.Fatalf("apply patch = %#v, %v", result, err)
	}
	got, _ = r.Read("a.txt")
	if got.Content != "one\nsecond\n" {
		t.Fatalf("patched a = %q", got.Content)
	}
	got, _ = r.Read("b.txt")
	if got.Content != "three\nfourth\n" {
		t.Fatalf("patched b = %q", got.Content)
	}
}

func TestApplyPatchRejectsUnsafeOperations(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "a.txt", "one\n")
	cases := []string{
		"--- a/../escape\n+++ b/../escape\n@@ -1 +1 @@\n-one\n+two\n",
		"--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+new\n",
		"--- a/a.txt\n+++ b/renamed.txt\n@@ -1 +1 @@\n-one\n+two\n",
	}
	for _, patch := range cases {
		if _, err := r.ApplyPatch(patch); err == nil {
			t.Fatalf("unsafe patch accepted: %q", patch)
		}
	}
}

func TestApplyPatchValidationErrors(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "a.txt", "one\n")

	// Empty patch.
	if _, err := r.ApplyPatch(""); err == nil {
		t.Fatal("empty patch accepted")
	}
	// CRLF patch.
	if _, err := r.ApplyPatch("--- a/a.txt\r\n+++ b/a.txt\r\n"); err == nil {
		t.Fatal("CRLF patch accepted")
	}
	// Patch with NUL byte.
	if _, err := r.ApplyPatch("--- a/a.txt\n+++ b/a.txt\n\x00"); err == nil {
		t.Fatal("patch with NUL accepted")
	}
	// Duplicate file path in single patch.
	dupPatch := "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-one\n+two\n" +
		"--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-two\n+three\n"
	if _, err := r.ApplyPatch(dupPatch); err == nil {
		t.Fatal("duplicate file patch accepted")
	}
}

func TestReadRangeAndStatEdgeCases(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "file.txt", "content")

	// ReadRange negative offset.
	if _, err := r.ReadRange("file.txt", -1, 5); err == nil {
		t.Fatal("negative offset accepted")
	}
	// ReadRange zero/negative length.
	if _, err := r.ReadRange("file.txt", 0, 0); err == nil {
		t.Fatal("zero length accepted")
	}
	if _, err := r.ReadRange("file.txt", 0, -5); err == nil {
		t.Fatal("negative length accepted")
	}

	// Stat empty path rejected.
	if _, err := r.Stat(""); err == nil {
		t.Fatal("stat empty path succeeded")
	}
	// Stat directory path.
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	dirStat, err := r.Stat("subdir")
	if err != nil || dirStat.Type != "directory" {
		t.Fatalf("subdir stat: %#v, %v", dirStat, err)
	}
	// Stat missing file.
	if _, err := r.Stat("nonexistent.txt"); err == nil {
		t.Fatal("stat missing file succeeded")
	}
}
