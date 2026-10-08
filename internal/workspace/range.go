//go:build linux

package workspace

import (
	"bytes"
	"errors"
	"os"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/limits"
	"golang.org/x/sys/unix"
)

type StatResult struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	ModTime string `json:"mod_time"`
}

// Stat reports metadata without following symlinks.
func (r *Root) Stat(p string) (StatResult, error) {
	if err := ValidatePath(p, false); err != nil {
		return StatResult{}, err
	}
	parent, base, err := r.openParent(p, false)
	if err != nil {
		return StatResult{}, errors.New("path is unavailable or unsafe")
	}
	defer unix.Close(parent)
	var st unix.Stat_t
	if err := unix.Fstatat(parent, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return StatResult{}, errors.New("path is unavailable or unsafe")
	}
	typ := "other"
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		typ = "file"
	case unix.S_IFDIR:
		typ = "directory"
	case unix.S_IFLNK:
		typ = "symlink"
	}
	return StatResult{
		Path: p, Type: typ, Size: st.Size, Mode: st.Mode & 0o7777,
		ModTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UTC().Format(time.RFC3339Nano),
	}, nil
}

type RangeResult struct {
	Path       string `json:"path"`
	Offset     int64  `json:"offset"`
	Content    string `json:"content"`
	Size       int64  `json:"size"`
	NextOffset int64  `json:"next_offset"`
}

// ReadRange returns one bounded byte range. The UTF-8/binary policy matches Read.
func (r *Root) ReadRange(p string, offset, length int64) (RangeResult, error) {
	if err := ValidatePath(p, false); err != nil {
		return RangeResult{}, err
	}
	if offset < 0 || length < 1 || length > int64(limits.MaxFileBytes) {
		return RangeResult{}, errors.New("range is outside allowed bounds")
	}
	fd, err := r.open(p, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return RangeResult{}, errors.New("file is unavailable or unsafe")
	}
	defer unix.Close(fd)
	st, err := regularInfo(fd)
	if err != nil {
		return RangeResult{}, err
	}
	if offset >= st.Size {
		return RangeResult{}, errors.New("offset is beyond end of file")
	}
	buf := make([]byte, min(length, st.Size-offset))
	n, err := unix.Pread(fd, buf, offset)
	if err != nil {
		return RangeResult{}, errors.New("file changed during read")
	}
	b := buf[:n]
	if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return RangeResult{}, errors.New("file is not UTF-8 text")
	}
	return RangeResult{
		Path: p, Offset: offset, Content: string(b), Size: st.Size, NextOffset: offset + int64(n),
	}, nil
}

// GlobResult is the structured result of Glob. Paths is never nil. When
// Truncated is true the list is incomplete and TruncatedReason says why, so a
// short or empty list is not mistaken for "no match".
type GlobResult struct {
	Paths           []string `json:"paths"`
	Truncated       bool     `json:"truncated"`
	TruncatedReason string   `json:"truncated_reason,omitempty"`
}

// Glob matches one slash-separated pattern below an optional root path.
// Components may use *, ?, and [...] character classes. Matches are
// deterministic and bounded; symlinks and .git are never traversed. Hitting a
// limit returns the matches found so far with Truncated set.
func (r *Root) Glob(pattern, rootPath string) (GlobResult, error) {
	if pattern == "" {
		return GlobResult{}, errors.New("pattern must not be empty")
	}
	if err := ValidatePath(rootPath, true); err != nil {
		return GlobResult{}, err
	}
	parts := strings.Split(pattern, "/")
	if len(parts) > limits.MaxParentDepth {
		return GlobResult{}, ErrUnsafePath
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.Contains(part, "\\") || len(part) > limits.MaxPathComponent {
			return GlobResult{}, ErrUnsafePath
		}
		if part == ".git" {
			return GlobResult{}, errors.New(".git is reserved")
		}
		if _, err := path.Match(part, ""); err != nil {
			return GlobResult{}, errors.New("invalid glob pattern")
		}
	}
	start, err := r.rootFD()
	if err != nil {
		return GlobResult{}, err
	}
	if rootPath != "" {
		unix.Close(start)
		start, err = r.open(rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return GlobResult{}, errors.New("glob root is unavailable or unsafe")
		}
	}
	type target struct {
		fd    int
		rel   string
		owned bool
	}
	closeTargets := func(ts []target) {
		for _, t := range ts {
			if t.owned {
				unix.Close(t.fd)
			}
		}
	}
	current := []target{{fd: start, rel: rootPath, owned: true}}
	defer func() { closeTargets(current) }()
	result := GlobResult{Paths: make([]string, 0)}
	truncate := func(reason string) {
		result.Truncated = true
		if result.TruncatedReason == "" {
			result.TruncatedReason = reason
		}
	}
	scanned := 0
outer:
	for i, part := range parts {
		last := i == len(parts)-1
		var next []target
		for _, t := range current {
			candidates := []string{part}
			if hasGlobMeta(part) {
				names, err := readDirNames(t.fd)
				if err != nil {
					continue
				}
				candidates = candidates[:0]
				for _, name := range names {
					ok, err := path.Match(part, name)
					if err != nil {
						closeTargets(next)
						return GlobResult{}, ErrUnsafePath
					}
					if ok {
						candidates = append(candidates, name)
					}
				}
			}
			for _, name := range candidates {
				scanned++
				if scanned > limits.MaxGlobScanEntries {
					truncate("scan entry limit reached; use a more specific pattern or a deeper `path`")
					closeTargets(next)
					break outer
				}
				if name == ".git" {
					continue
				}
				var st unix.Stat_t
				if unix.Fstatat(t.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT == unix.S_IFLNK {
					continue
				}
				rel := joinRel(t.rel, name)
				if last {
					if len(result.Paths) >= limits.MaxGlobResults {
						truncate("result limit reached; use a more specific pattern")
						closeTargets(next)
						break outer
					}
					result.Paths = append(result.Paths, rel)
					continue
				}
				if st.Mode&unix.S_IFMT != unix.S_IFDIR || ignoredDirectory(name) {
					continue
				}
				child, err := openAt(t.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
				if err != nil {
					continue
				}
				next = append(next, target{fd: child, rel: rel, owned: true})
			}
		}
		closeTargets(current)
		current = next
		if len(result.Paths)+len(current) > limits.MaxGlobResults {
			truncate("too many intermediate directories; use a more specific pattern")
			break outer
		}
	}
	sort.Strings(result.Paths)
	return result, nil
}

func joinRel(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

func hasGlobMeta(part string) bool {
	return strings.ContainsAny(part, "*?[")
}

func readDirNames(dirfd int) ([]string, error) {
	fd, err := openAt(dirfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "workspace-directory")
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}
