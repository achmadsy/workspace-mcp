//go:build linux

// Package workspace provides race-safe, fd-relative access to one workspace.
package workspace

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const resolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

type Root struct {
	fd      int
	mu      sync.RWMutex
	writeMu sync.Mutex
	closed  bool
}

func OpenRoot(path string) (*Root, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open workspace root: %w", err)
	}
	r := &Root{fd: fd}
	// Probe syscall and all required resolution flags. Empty path must fail with
	// ENOENT, not ENOSYS/EINVAL; opening "." proves usable resolution semantics.
	probe, err := unix.Openat2(fd, ".", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: resolveFlags})
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("openat2 with required security flags unavailable: %w", err)
	}
	unix.Close(probe)
	return r, nil
}

func (r *Root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return unix.Close(r.fd)
}

func (r *Root) rootFD() (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return -1, fs.ErrClosed
	}
	fd, err := unix.Dup(r.fd)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

func openAt(dirfd int, path string, flags int, mode uint32) (int, error) {
	return unix.Openat2(dirfd, path, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Mode: uint64(mode), Resolve: resolveFlags})
}

func (r *Root) open(path string, flags int, mode uint32) (int, error) {
	rootfd, err := r.rootFD()
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootfd)
	return openAt(rootfd, path, flags, mode)
}

// HasGitDir verifies a workspace-local, non-symlink .git directory without
// allowing parent repository discovery.
func (r *Root) HasGitDir() bool {
	fd, err := r.open(".git", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// ProcPath returns a process-local path bound to an open duplicate of the root
// directory. The cleanup closes that duplicate; callers must keep it open for
// the lifetime of any child process using the path.
func (r *Root) ProcPath() (path string, cleanup func(), err error) {
	fd, err := r.rootFD()
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("/proc/self/fd/%d", fd), func() { _ = unix.Close(fd) }, nil
}

// SandboxFile returns a duplicated workspace descriptor suitable for passing
// through exec.Cmd.ExtraFiles. Caller owns returned file.
func (r *Root) SandboxFile() (*os.File, error) {
	fd, err := r.rootFD()
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "workspace-root"), nil
}

func regularInfo(fd int) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return st, errors.New("path is not a regular file")
	}
	if st.Nlink != 1 {
		return st, errors.New("multiply-linked files are not allowed")
	}
	return st, nil
}

func readBounded(fd int, max int64) ([]byte, unix.Stat_t, error) {
	st, err := regularInfo(fd)
	if err != nil {
		return nil, st, err
	}
	if st.Size > max {
		return nil, st, errors.New("file exceeds size limit")
	}
	f := newFDFile(fd)
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, st, err
	}
	if int64(len(b)) > max {
		return nil, st, errors.New("file exceeds size limit")
	}
	return b, st, nil
}

type fdReader struct{ fd int }

func newFDFile(fd int) *fdReader { return &fdReader{fd: fd} }
func (f *fdReader) Read(p []byte) (int, error) {
	n, err := unix.Read(f.fd, p)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}
