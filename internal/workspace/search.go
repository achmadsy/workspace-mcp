//go:build linux

package workspace

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/limits"
	"golang.org/x/sys/unix"
)

type SearchMatch struct {
	RelativePath string `json:"relative_path"`
	LineNumber   int    `json:"line_number"`
	MatchingLine string `json:"matching_line"`
}
type SearchResult struct {
	Matches      []SearchMatch `json:"matches"`
	FilesScanned int           `json:"files_scanned"`
	BytesScanned int64         `json:"bytes_scanned"`
	Truncated    bool          `json:"truncated"`
}

func (r *Root) Search(ctx context.Context, query, path string, maxResults int) (SearchResult, error) {
	if query == "" {
		return SearchResult{}, errors.New("query must not be empty")
	}
	if !utf8.ValidString(query) || strings.IndexByte(query, 0) >= 0 {
		return SearchResult{}, errors.New("query must be UTF-8 text")
	}
	if err := ValidatePath(path, true); err != nil {
		return SearchResult{}, err
	}
	if maxResults == 0 {
		maxResults = limits.DefaultSearchResults
	}
	if maxResults < 1 || maxResults > limits.MaxSearchResults {
		return SearchResult{}, errors.New("max_results is outside allowed range")
	}
	result := SearchResult{Matches: make([]SearchMatch, 0)}
	start, err := r.rootFD()
	if err != nil {
		return result, err
	}
	startPrefix := path
	if path != "" {
		unix.Close(start)
		start, err = r.open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return result, errors.New("search path is unavailable or unsafe")
		}
	}
	defer unix.Close(start)
	var startStat unix.Stat_t
	if err := unix.Fstat(start, &startStat); err != nil {
		return result, err
	}
	var scanFile func(int, string) error
	scanFile = func(fd int, rel string) error {
		if result.FilesScanned >= limits.MaxSearchFiles || result.BytesScanned >= limits.MaxSearchBytes {
			result.Truncated = true
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
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 4096), limits.MaxSearchLineBytes)
		lineNo := 0
		local := make([]SearchMatch, 0)
		for s.Scan() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			lineNo++
			b := s.Bytes()
			result.BytesScanned += int64(len(b) + 1)
			if result.BytesScanned > limits.MaxSearchBytes {
				result.Truncated = true
				return nil
			}
			if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
				return nil
			}
			if bytes.Contains(b, []byte(query)) {
				local = append(local, SearchMatch{RelativePath: rel, LineNumber: lineNo, MatchingLine: string(b)})
			}
		}
		if err := s.Err(); err != nil {
			return nil
		} // skip binary/overlong/changed files
		result.FilesScanned++
		for _, m := range local {
			if len(result.Matches) >= maxResults {
				result.Truncated = true
				return nil
			}
			result.Matches = append(result.Matches, m)
		}
		return nil
	}
	var walk func(int, string) error
	walk = func(dirfd int, prefix string) error {
		dup, err := unix.Dup(dirfd)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(dup), "workspace-directory")
		entries, err := f.ReadDir(-1)
		f.Close()
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, de := range entries {
			if result.Truncated {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			name := de.Name()
			if name == ".git" || ignoredDirectory(name) {
				continue
			}
			var st unix.Stat_t
			if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				continue
			}
			rel := name
			if prefix != "" {
				rel = prefix + "/" + name
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
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
		err = scanFile(start, path)
	} else if startStat.Mode&unix.S_IFMT == unix.S_IFDIR {
		err = walk(start, startPrefix)
	} else {
		err = errors.New("search path must be a regular file or directory")
	}
	return result, err
}
