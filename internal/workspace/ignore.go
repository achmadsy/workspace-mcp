//go:build linux

package workspace

import (
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// maxIgnoreFileBytes bounds how much of the root .gitignore is read.
const maxIgnoreFileBytes = 64 << 10

type ignorePattern struct {
	glob string
	// anchored patterns match the full workspace-relative path; the others match
	// the directory name at any depth.
	anchored bool
}

// ignoreRules holds simple directory patterns taken from the root .gitignore.
// It is deliberately small: blank lines and comments are skipped, a trailing
// slash is accepted, a leading or inner slash anchors the pattern to the
// workspace root, a leading "**/" is treated as unanchored, and anything with
// negation or other "**" use is ignored. Only directories are ever skipped, so
// a pattern that over-matches a file name is harmless. All methods are safe on
// a nil receiver.
type ignoreRules struct {
	patterns []ignorePattern
}

// loadIgnoreRules reads the root .gitignore. It never returns nil; a missing,
// unsafe or oversized file yields empty rules.
func (r *Root) loadIgnoreRules() *ignoreRules {
	rules := &ignoreRules{}
	fd, err := r.open(".gitignore", unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return rules
	}
	st, err := regularInfo(fd)
	if err != nil || st.Size > maxIgnoreFileBytes {
		unix.Close(fd)
		return rules
	}
	f := os.NewFile(uintptr(fd), "workspace-gitignore")
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxIgnoreFileBytes))
	if err != nil {
		return rules
	}
	rules.parse(string(data))
	return rules
}

func (g *ignoreRules) parse(content string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r \t")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		line = strings.TrimSuffix(line, "/")
		anchored := false
		if strings.HasPrefix(line, "/") {
			anchored = true
			line = strings.TrimLeft(line, "/")
		}
		for strings.HasPrefix(line, "**/") {
			line = strings.TrimPrefix(line, "**/")
			anchored = false
		}
		if line == "" || strings.Contains(line, "**") {
			continue
		}
		if strings.Contains(line, "/") {
			anchored = true
		}
		if _, err := path.Match(line, "probe"); err != nil {
			continue
		}
		g.patterns = append(g.patterns, ignorePattern{glob: line, anchored: anchored})
	}
}

// matches reports whether a directory is ignored by the loaded patterns. rel is
// the workspace-relative path and name its last component. Files are never
// skipped, so isDir false always returns false.
func (g *ignoreRules) matches(rel, name string, isDir bool) bool {
	if g == nil || !isDir {
		return false
	}
	for _, p := range g.patterns {
		target := name
		if p.anchored {
			target = rel
		}
		if ok, _ := path.Match(p.glob, target); ok {
			return true
		}
	}
	return false
}

// coversPath reports whether p lies inside an ignored directory, either by the
// built-in list or by the loaded patterns. A search that starts there is an
// explicit request and is not filtered.
func (g *ignoreRules) coversPath(p string) bool {
	if p == "" {
		return false
	}
	rel := ""
	for _, part := range strings.Split(p, "/") {
		if rel == "" {
			rel = part
		} else {
			rel += "/" + part
		}
		if ignoredDirectory(part) || g.matches(rel, part, true) {
			return true
		}
	}
	return false
}
