//go:build linux

package workspace

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/link/workspace-mcp/internal/limits"
	"golang.org/x/sys/unix"
)

func (r *Root) openParent(path string, create bool) (int, string, error) {
	parts := strings.Split(path, "/")
	base := parts[len(parts)-1]
	fd, err := r.rootFD()
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := openAt(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if openErr != nil && create && errors.Is(openErr, unix.ENOENT) {
			if mkErr := unix.Mkdirat(fd, part, 0o755); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
				unix.Close(fd)
				return -1, "", fmt.Errorf("create parent directory: %w", mkErr)
			}
			next, openErr = openAt(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		}
		unix.Close(fd)
		if openErr != nil {
			return -1, "", fmt.Errorf("open parent directory: %w", openErr)
		}
		fd = next
	}
	return fd, base, nil
}

func (r *Root) atomicWrite(path string, content []byte) (changed bool, err error) {
	if len(content) > limits.MaxWriteBytes {
		return false, errors.New("content exceeds write limit")
	}
	parent, base, err := r.openParent(path, true)
	if err != nil {
		return false, err
	}
	defer unix.Close(parent)
	mode := uint32(0o644)
	oldfd, openErr := openAt(parent, base, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if openErr == nil {
		old, st, readErr := readBounded(oldfd, int64(limits.MaxFileBytes))
		unix.Close(oldfd)
		if readErr != nil {
			return false, readErr
		}
		mode = uint32(st.Mode & 0o777)
		if string(old) == string(content) {
			return false, nil
		}
	} else if !errors.Is(openErr, unix.ENOENT) {
		return false, fmt.Errorf("inspect destination: %w", openErr)
	}
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return false, errors.New("generate temporary name")
	}
	tmp := ".workspace-mcp-" + hex.EncodeToString(rnd[:])
	tfd, err := unix.Openat(parent, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return false, fmt.Errorf("create temporary file: %w", err)
	}
	cleanup := true
	defer func() {
		unix.Close(tfd)
		if cleanup {
			unix.Unlinkat(parent, tmp, 0)
		}
	}()
	for len(content) > 0 {
		n, writeErr := unix.Write(tfd, content)
		if writeErr != nil {
			return false, fmt.Errorf("write temporary file: %w", writeErr)
		}
		content = content[n:]
	}
	if err := unix.Fsync(tfd); err != nil {
		return false, fmt.Errorf("sync temporary file: %w", err)
	}
	if err := unix.Renameat(parent, tmp, parent, base); err != nil {
		return false, fmt.Errorf("replace destination: %w", err)
	}
	cleanup = false
	if err := unix.Fsync(parent); err != nil {
		return false, fmt.Errorf("sync parent directory: %w", err)
	}
	return true, nil
}
