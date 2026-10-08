//go:build linux

package workspace

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/limits"
	"golang.org/x/sys/unix"
)

type SearchOptions struct {
	Path            string
	MaxResults      int
	CaseInsensitive bool
	Include         []string
	ContextLines    int
	// IncludeIgnored also searches directories skipped by default (built-in
	// dependency/build directories and simple patterns from the root .gitignore).
	IncludeIgnored bool
}

type SearchMatch struct {
	RelativePath string   `json:"relative_path"`
	LineNumber   int      `json:"line_number"`
	MatchingLine string   `json:"matching_line"`
	Before       []string `json:"before,omitempty"`
	After        []string `json:"after,omitempty"`
}

type SearchResult struct {
	Matches      []SearchMatch `json:"matches"`
	FilesScanned int           `json:"files_scanned"`
	BytesScanned int64         `json:"bytes_scanned"`
	Truncated    bool          `json:"truncated"`
	// TruncatedReason says why the search stopped early, so an empty result is
	// not mistaken for "no match".
	TruncatedReason string `json:"truncated_reason,omitempty"`
	// SkippedDirs lists (a bounded sample of) directories skipped as ignored.
	SkippedDirs []string `json:"skipped_dirs,omitempty"`
}

const maxSkippedDirs = 25

func (r *Root) Search(ctx context.Context, query, searchPath string, maxResults int) (SearchResult, error) {
	return r.SearchWithOptions(ctx, query, SearchOptions{Path: searchPath, MaxResults: maxResults})
}

func (r *Root) SearchWithOptions(ctx context.Context, query string, options SearchOptions) (SearchResult, error) {
	if query == "" {
		return SearchResult{}, errors.New("query must not be empty")
	}
	if !utf8.ValidString(query) || strings.IndexByte(query, 0) >= 0 {
		return SearchResult{}, errors.New("query must be UTF-8 text")
	}
	if err := ValidatePath(options.Path, true); err != nil {
		return SearchResult{}, err
	}
	if options.MaxResults == 0 {
		options.MaxResults = limits.DefaultSearchResults
	}
	if options.MaxResults < 1 || options.MaxResults > limits.MaxSearchResults {
		return SearchResult{}, errors.New("max_results is outside allowed range")
	}
	if options.ContextLines < 0 || options.ContextLines > limits.MaxSearchContextLines {
		return SearchResult{}, errors.New("context_lines is outside allowed range")
	}
	if len(options.Include) > limits.MaxSearchIncludeGlobs {
		return SearchResult{}, errors.New("too many include globs")
	}
	for _, pattern := range options.Include {
		if pattern == "" {
			return SearchResult{}, errors.New("include glob must not be empty")
		}
		if _, err := path.Match(pattern, "probe"); err != nil {
			return SearchResult{}, errors.New("invalid include glob")
		}
	}

	needle := query
	if options.CaseInsensitive {
		needle = strings.ToLower(query)
	}
	result := SearchResult{Matches: make([]SearchMatch, 0)}
	start, err := r.rootFD()
	if err != nil {
		return result, err
	}
	startPrefix := options.Path
	if options.Path != "" {
		unix.Close(start)
		start, err = r.open(options.Path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return result, errors.New("search path is unavailable or unsafe")
		}
	}
	defer unix.Close(start)
	var startStat unix.Stat_t
	if err := unix.Fstat(start, &startStat); err != nil {
		return result, err
	}

	skipIgnored := !options.IncludeIgnored
	var rules *ignoreRules
	if skipIgnored {
		rules = r.loadIgnoreRules()
		if rules.coversPath(options.Path) {
			// The caller asked for a location inside an ignored directory.
			skipIgnored = false
		}
	}
	truncate := func(reason string) {
		result.Truncated = true
		if result.TruncatedReason == "" {
			result.TruncatedReason = reason
		}
	}
	skipDir := func(rel, name string) bool {
		if !skipIgnored || (!ignoredDirectory(name) && !rules.matches(rel, name, true)) {
			return false
		}
		if len(result.SkippedDirs) < maxSkippedDirs {
			result.SkippedDirs = append(result.SkippedDirs, rel)
		}
		return true
	}

	scanFile := func(fd int, rel string) error {
		if result.FilesScanned >= limits.MaxSearchFiles || result.BytesScanned >= limits.MaxSearchBytes {
			truncate("scan budget exhausted (file or byte limit); narrow `path` or use `include`")
			return nil
		}
		if !matchesIncludes(rel, options.Include) {
			return nil
		}
		if _, err := regularInfo(fd); err != nil {
			return nil
		}
		dup, err := unix.Dup(fd)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(dup), "workspace-file")
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), limits.MaxSearchLineBytes)
		lines := make([]string, 0)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			b := scanner.Bytes()
			result.BytesScanned += int64(len(b) + 1)
			if result.BytesScanned > limits.MaxSearchBytes {
				truncate("scan budget exhausted (file or byte limit); narrow `path` or use `include`")
				return nil
			}
			if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
				return nil
			}
			lines = append(lines, string(b))
		}
		if scanner.Err() != nil {
			return nil
		}
		result.FilesScanned++
		for i, line := range lines {
			candidate := line
			if options.CaseInsensitive {
				candidate = strings.ToLower(candidate)
			}
			if !strings.Contains(candidate, needle) {
				continue
			}
			if len(result.Matches) >= options.MaxResults {
				truncate("max_results reached; raise max_results or narrow the query")
				return nil
			}
			match := SearchMatch{RelativePath: rel, LineNumber: i + 1, MatchingLine: line}
			if options.ContextLines > 0 {
				before := max(0, i-options.ContextLines)
				after := min(len(lines), i+options.ContextLines+1)
				match.Before = append([]string(nil), lines[before:i]...)
				match.After = append([]string(nil), lines[i+1:after]...)
			}
			if searchResultSize(result.Matches)+searchMatchSize(match) > limits.MaxSearchResultBytes {
				truncate("result size limit reached; narrow the query or reduce context_lines")
				return nil
			}
			result.Matches = append(result.Matches, match)
		}
		return nil
	}

	var walk func(int, string) error
	walk = func(dirfd int, prefix string) error {
		names, err := readDirNames(dirfd)
		if err != nil {
			return err
		}
		for _, name := range names {
			if result.Truncated {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if name == ".git" {
				continue
			}
			var st unix.Stat_t
			if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				continue
			}
			rel := joinRel(prefix, name)
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				if skipDir(rel, name) {
					continue
				}
				child, err := openAt(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
				if err != nil {
					return errors.New("directory changed or became unsafe during search")
				}
				err = walk(child, rel)
				unix.Close(child)
				if err != nil {
					return err
				}
			case unix.S_IFREG:
				filefd, err := openAt(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
				if err != nil {
					continue
				}
				err = scanFile(filefd, rel)
				unix.Close(filefd)
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
	if startStat.Mode&unix.S_IFMT == unix.S_IFREG {
		err = scanFile(start, options.Path)
	} else if startStat.Mode&unix.S_IFMT == unix.S_IFDIR {
		err = walk(start, startPrefix)
	} else {
		err = errors.New("search path must be a regular file or directory")
	}
	return result, err
}

func searchResultSize(matches []SearchMatch) int {
	total := 0
	for _, match := range matches {
		total += searchMatchSize(match)
	}
	return total
}

func searchMatchSize(match SearchMatch) int {
	total := len(match.RelativePath) + len(match.MatchingLine) + 32
	for _, line := range match.Before {
		total += len(line)
	}
	for _, line := range match.After {
		total += len(line)
	}
	return total
}

func matchesIncludes(rel string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	base := path.Base(rel)
	for _, pattern := range patterns {
		matched, _ := path.Match(pattern, rel)
		if !matched && !strings.Contains(pattern, "/") {
			matched, _ = path.Match(pattern, base)
		}
		if matched {
			return true
		}
	}
	return false
}
