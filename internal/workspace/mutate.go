//go:build linux

package workspace

import (
	"errors"
	"fmt"

	"github.com/link/workspace-mcp/internal/limits"
	"golang.org/x/sys/unix"
)

type MutationResult struct {
	Path    string `json:"path"`
	Changed bool   `json:"changed"`
}

type MoveResult struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Changed     bool   `json:"changed"`
}

// Mkdir creates one directory. With parents=true, missing parents are created.
func (r *Root) Mkdir(p string, parents bool) (MutationResult, error) {
	if err := ValidatePath(p, false); err != nil {
		return MutationResult{}, err
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	parent, base, err := r.openParent(p, parents)
	if err != nil {
		return MutationResult{}, err
	}
	defer unix.Close(parent)
	if err := unix.Mkdirat(parent, base, 0o755); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return MutationResult{}, fmt.Errorf("create directory: %w", err)
		}
		fd, openErr := openAt(parent, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return MutationResult{}, errors.New("destination exists and is not a safe directory")
		}
		unix.Close(fd)
		return MutationResult{Path: p}, nil
	}
	if err := unix.Fsync(parent); err != nil {
		return MutationResult{}, fmt.Errorf("sync parent directory: %w", err)
	}
	return MutationResult{Path: p, Changed: true}, nil
}

// Delete removes one regular file or, when recursive is true, one bounded tree.
// Symlink targets are always rejected rather than unlinked.
func (r *Root) Delete(p string, recursive bool) (MutationResult, error) {
	if err := ValidatePath(p, false); err != nil {
		return MutationResult{}, err
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	parent, base, err := r.openParent(p, false)
	if err != nil {
		return MutationResult{}, errors.New("path is unavailable or unsafe")
	}
	defer unix.Close(parent)
	var st unix.Stat_t
	if err := unix.Fstatat(parent, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return MutationResult{}, errors.New("path is unavailable or unsafe")
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		fd, err := openAt(parent, base, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return MutationResult{}, errors.New("file changed or became unsafe")
		}
		_, err = regularInfo(fd)
		unix.Close(fd)
		if err != nil {
			return MutationResult{}, err
		}
		if err := unix.Unlinkat(parent, base, 0); err != nil {
			return MutationResult{}, fmt.Errorf("delete file: %w", err)
		}
	case unix.S_IFDIR:
		if !recursive {
			return MutationResult{}, errors.New("recursive=true is required to delete a directory")
		}
		fd, err := openAt(parent, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return MutationResult{}, errors.New("directory changed or became unsafe")
		}
		count := 0
		if err := inspectTree(fd, &count); err != nil {
			unix.Close(fd)
			return MutationResult{}, err
		}
		err = removeTree(fd)
		unix.Close(fd)
		if err != nil {
			return MutationResult{}, err
		}
		if err := unix.Unlinkat(parent, base, unix.AT_REMOVEDIR); err != nil {
			return MutationResult{}, fmt.Errorf("delete directory: %w", err)
		}
	default:
		return MutationResult{}, errors.New("only regular files and directories may be deleted")
	}
	if err := unix.Fsync(parent); err != nil {
		return MutationResult{}, fmt.Errorf("sync parent directory: %w", err)
	}
	return MutationResult{Path: p, Changed: true}, nil
}

func inspectTree(dirfd int, count *int) error {
	names, err := readDirNames(dirfd)
	if err != nil {
		return err
	}
	for _, name := range names {
		*count = *count + 1
		if *count > limits.MaxRecursiveDeleteEntries {
			return errors.New("recursive delete exceeds entry limit")
		}
		var st unix.Stat_t
		if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return errors.New("entry changed during recursive delete")
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			fd, err := openAt(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
			if err != nil {
				return errors.New("file changed or became unsafe during recursive delete")
			}
			_, err = regularInfo(fd)
			unix.Close(fd)
			if err != nil {
				return err
			}
		case unix.S_IFDIR:
			child, err := openAt(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			if err != nil {
				return errors.New("directory changed or became unsafe during recursive delete")
			}
			err = inspectTree(child, count)
			unix.Close(child)
			if err != nil {
				return err
			}
		default:
			return errors.New("recursive delete encountered unsupported or unsafe entry")
		}
	}
	return nil
}

func removeTree(dirfd int) error {
	names, err := readDirNames(dirfd)
	if err != nil {
		return err
	}
	for _, name := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return errors.New("entry changed during recursive delete")
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			fd, err := openAt(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
			if err != nil {
				return errors.New("file changed or became unsafe during recursive delete")
			}
			_, err = regularInfo(fd)
			unix.Close(fd)
			if err != nil {
				return err
			}
			if err := unix.Unlinkat(dirfd, name, 0); err != nil {
				return err
			}
		case unix.S_IFDIR:
			child, err := openAt(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			if err != nil {
				return errors.New("directory changed or became unsafe during recursive delete")
			}
			err = removeTree(child)
			unix.Close(child)
			if err != nil {
				return err
			}
			if err := unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR); err != nil {
				return err
			}
		default:
			return errors.New("recursive delete encountered unsupported or unsafe entry")
		}
	}
	return unix.Fsync(dirfd)
}

// Move atomically renames one safe file or directory. Destination parents must exist.
func (r *Root) Move(source, destination string, overwrite bool) (MoveResult, error) {
	if err := ValidatePath(source, false); err != nil {
		return MoveResult{}, err
	}
	if err := ValidatePath(destination, false); err != nil {
		return MoveResult{}, err
	}
	if source == destination {
		return MoveResult{Source: source, Destination: destination}, nil
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	srcParent, srcBase, err := r.openParent(source, false)
	if err != nil {
		return MoveResult{}, errors.New("source is unavailable or unsafe")
	}
	defer unix.Close(srcParent)
	dstParent, dstBase, err := r.openParent(destination, false)
	if err != nil {
		return MoveResult{}, errors.New("destination parent is unavailable or unsafe")
	}
	defer unix.Close(dstParent)
	var srcStat unix.Stat_t
	if err := unix.Fstatat(srcParent, srcBase, &srcStat, unix.AT_SYMLINK_NOFOLLOW); err != nil || srcStat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return MoveResult{}, errors.New("source is unavailable or unsafe")
	}
	switch srcStat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		fd, err := openAt(srcParent, srcBase, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return MoveResult{}, errors.New("source changed or became unsafe")
		}
		_, err = regularInfo(fd)
		unix.Close(fd)
		if err != nil {
			return MoveResult{}, err
		}
	case unix.S_IFDIR:
		fd, err := openAt(srcParent, srcBase, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return MoveResult{}, errors.New("source changed or became unsafe")
		}
		count := 0
		err = inspectTree(fd, &count)
		unix.Close(fd)
		if err != nil {
			return MoveResult{}, err
		}
	default:
		return MoveResult{}, errors.New("only regular files and directories may be moved")
	}
	if overwrite {
		var dstStat unix.Stat_t
		if err := unix.Fstatat(dstParent, dstBase, &dstStat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			switch dstStat.Mode & unix.S_IFMT {
			case unix.S_IFLNK:
				return MoveResult{}, errors.New("destination symlink is unsafe")
			case unix.S_IFREG:
				fd, openErr := openAt(dstParent, dstBase, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
				if openErr != nil {
					return MoveResult{}, errors.New("destination changed or became unsafe")
				}
				_, openErr = regularInfo(fd)
				unix.Close(fd)
				if openErr != nil {
					return MoveResult{}, openErr
				}
			case unix.S_IFDIR:
				fd, openErr := openAt(dstParent, dstBase, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
				if openErr != nil {
					return MoveResult{}, errors.New("destination changed or became unsafe")
				}
				count := 0
				openErr = inspectTree(fd, &count)
				unix.Close(fd)
				if openErr != nil {
					return MoveResult{}, openErr
				}
			default:
				return MoveResult{}, errors.New("destination type is unsupported")
			}
		} else if !errors.Is(err, unix.ENOENT) {
			return MoveResult{}, errors.New("destination is unavailable or unsafe")
		}
	}
	flags := uint(0)
	if !overwrite {
		flags = unix.RENAME_NOREPLACE
	}
	if err := unix.Renameat2(srcParent, srcBase, dstParent, dstBase, flags); err != nil {
		return MoveResult{}, fmt.Errorf("move path: %w", err)
	}
	if err := unix.Fsync(srcParent); err != nil {
		return MoveResult{}, fmt.Errorf("sync source parent: %w", err)
	}
	if err := unix.Fsync(dstParent); err != nil {
		return MoveResult{}, fmt.Errorf("sync destination parent: %w", err)
	}
	return MoveResult{Source: source, Destination: destination, Changed: true}, nil
}

// Copy copies one regular, single-linked file through atomicWrite.
func (r *Root) Copy(source, destination string, overwrite bool) (MoveResult, error) {
	if err := ValidatePath(source, false); err != nil {
		return MoveResult{}, err
	}
	if err := ValidatePath(destination, false); err != nil {
		return MoveResult{}, err
	}
	if source == destination {
		return MoveResult{Source: source, Destination: destination}, nil
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	fd, err := r.open(source, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return MoveResult{}, errors.New("source is unavailable or unsafe")
	}
	content, _, err := readBounded(fd, int64(limits.MaxFileBytes))
	unix.Close(fd)
	if err != nil {
		return MoveResult{}, err
	}
	changed, err := r.atomicWriteMode(destination, content, overwrite)
	if err != nil {
		return MoveResult{}, err
	}
	return MoveResult{Source: source, Destination: destination, Changed: changed}, nil
}
