package workspace

import (
	"bytes"
	"errors"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/limits"
	"golang.org/x/sys/unix"
)

type ReadResult struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
}

func (r *Root) Read(path string) (ReadResult, error) {
	if err := ValidatePath(path, false); err != nil {
		return ReadResult{}, err
	}
	fd, err := r.open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ReadResult{}, errors.New("file is unavailable or unsafe")
	}
	defer unix.Close(fd)
	b, st, err := readBounded(fd, int64(limits.MaxFileBytes))
	if err != nil {
		return ReadResult{}, err
	}
	if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return ReadResult{}, errors.New("file is not UTF-8 text")
	}
	return ReadResult{Path: path, Content: string(b), Size: st.Size}, nil
}
