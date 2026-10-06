//go:build linux

package workspace

import (
	"encoding/json"
	"errors"
	"os"
	"sort"

	"github.com/link/workspace-mcp/internal/limits"
	"golang.org/x/sys/unix"
)

type ListEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
}
type ListResult struct {
	Entries   []ListEntry `json:"entries"`
	Truncated bool        `json:"truncated"`
}

func (r *Root) List(path string, depth int) (ListResult, error) {
	if err := ValidatePath(path, true); err != nil {
		return ListResult{}, err
	}
	if depth == 0 {
		depth = limits.DefaultListDepth
	}
	if depth < 1 || depth > limits.MaxListDepth {
		return ListResult{}, errors.New("depth is outside allowed range")
	}
	fd, err := r.rootFD()
	if err != nil {
		return ListResult{}, err
	}
	if path != "" {
		unix.Close(fd)
		fd, err = r.open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return ListResult{}, errors.New("directory is unavailable or unsafe")
		}
	}
	result := ListResult{Entries: make([]ListEntry, 0)}
	used := 0
	var walk func(int, string, int) error
	walk = func(dirfd int, prefix string, remaining int) error {
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
			name := de.Name()
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
			rel := name
			if prefix != "" {
				rel = prefix + "/" + name
			}
			typ := "other"
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFREG:
				typ = "file"
			case unix.S_IFDIR:
				typ = "directory"
			}
			entry := ListEntry{Path: rel, Type: typ}
			if typ == "file" {
				entry.Size = st.Size
			}
			encoded, _ := json.Marshal(entry)
			if len(result.Entries) >= limits.MaxListEntries || used+len(encoded) > limits.MaxListResultBytes {
				result.Truncated = true
				return nil
			}
			result.Entries = append(result.Entries, entry)
			used += len(encoded)
			if typ == "directory" && remaining > 1 && !ignoredDirectory(name) {
				child, err := openAt(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
				if err != nil {
					return errors.New("directory changed or became unsafe during traversal")
				}
				err = walk(child, rel, remaining-1)
				unix.Close(child)
				if err != nil || result.Truncated {
					return err
				}
			}
		}
		return nil
	}
	err = walk(fd, path, depth)
	unix.Close(fd)
	if err != nil {
		return ListResult{}, err
	}
	return result, nil
}
