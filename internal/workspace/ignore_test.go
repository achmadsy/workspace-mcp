//go:build linux

package workspace

import (
	"sort"
	"testing"
)

func TestIgnoreRulesParseAndMatch(t *testing.T) {
	t.Parallel()

	rules := &ignoreRules{}
	rules.parse("# comment\n\n!keep\n/gen\nlogs/\n**/cache\n*.tmp\nout/**\nsrc/generated\n")

	cases := []struct {
		rel, name string
		isDir     bool
		want      bool
	}{
		{"gen", "gen", true, true},
		{"deep/gen", "gen", true, false}, // leading slash anchors to the root
		{"logs", "logs", true, true},
		{"a/b/logs", "logs", true, true}, // no slash: any depth
		{"a/cache", "cache", true, true}, // leading **/ is unanchored
		{"x.tmp", "x.tmp", true, true},
		{"x.tmp", "x.tmp", false, false}, // files are never skipped
		{"keep", "keep", true, false},    // negation lines are ignored
		{"out", "out", true, false},      // other ** forms are ignored
		{"src/generated", "generated", true, true},
		{"other/src/generated", "generated", true, false}, // inner slash anchors
	}
	for _, c := range cases {
		if got := rules.matches(c.rel, c.name, c.isDir); got != c.want {
			t.Errorf("matches(%q, %q, %t) = %t, want %t", c.rel, c.name, c.isDir, got, c.want)
		}
	}

	var nilRules *ignoreRules
	if nilRules.matches("gen", "gen", true) || nilRules.coversPath("gen") {
		t.Error("nil rules must match nothing")
	}
	if !rules.coversPath("gen/sub/file.go") || !rules.coversPath(".tools/go") || !rules.coversPath("a/node_modules") {
		t.Error("coversPath missed an ignored ancestor")
	}
	if rules.coversPath("") || rules.coversPath("src/main.go") {
		t.Error("coversPath matched a normal path")
	}
}

func TestSearchSkipsIgnoredDirectories(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, ".gitignore", "/gen\nlogs/\n")
	for _, rel := range []string{
		"src/a.go", ".tools/go/x.go", "gen/b.go", "logs/c.txt", "deep/logs/d.txt", "deep/gen/e.go",
	} {
		mustWrite(t, dir, rel, "needle\n")
	}

	paths := func(res SearchResult) []string {
		out := make([]string, 0, len(res.Matches))
		for _, m := range res.Matches {
			out = append(out, m.RelativePath)
		}
		sort.Strings(out)
		return out
	}
	equal := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	res, err := r.SearchWithOptions(t.Context(), "needle", SearchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// /gen is anchored, so deep/gen is still searched; logs/ matches at any depth.
	if got, want := paths(res), []string{"deep/gen/e.go", "src/a.go"}; !equal(got, want) {
		t.Fatalf("default search = %v, want %v", got, want)
	}
	if res.Truncated || len(res.SkippedDirs) == 0 {
		t.Fatalf("expected skipped dirs and no truncation: %#v", res)
	}

	res, err = r.SearchWithOptions(t.Context(), "needle", SearchOptions{IncludeIgnored: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := paths(res); len(got) != 6 || len(res.SkippedDirs) != 0 {
		t.Fatalf("include_ignored search = %v skipped = %v", got, res.SkippedDirs)
	}

	// Starting inside an ignored directory is an explicit request.
	res, err = r.SearchWithOptions(t.Context(), "needle", SearchOptions{Path: ".tools/go"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := paths(res), []string{".tools/go/x.go"}; !equal(got, want) {
		t.Fatalf("search inside ignored dir = %v, want %v", got, want)
	}
}

func TestSearchTruncationReason(t *testing.T) {
	r, dir := testRoot(t)
	mustWrite(t, dir, "a.txt", "needle\nneedle\nneedle\n")
	res, err := r.SearchWithOptions(t.Context(), "needle", SearchOptions{MaxResults: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || res.TruncatedReason == "" || len(res.Matches) != 2 {
		t.Fatalf("truncation not explained: %#v", res)
	}
}
