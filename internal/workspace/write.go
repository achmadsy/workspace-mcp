package workspace

import (
	"errors"
	"strings"
	"unicode/utf8"
)

type WriteResult struct {
	Path    string `json:"path"`
	Size    int    `json:"size"`
	Changed bool   `json:"changed"`
}

func (r *Root) Write(path, content string) (WriteResult, error) {
	if err := ValidatePath(path, false); err != nil {
		return WriteResult{}, err
	}
	if !utf8.ValidString(content) || strings.IndexByte(content, 0) >= 0 {
		return WriteResult{}, errors.New("content must be UTF-8 text without NUL bytes")
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	changed, err := r.atomicWrite(path, []byte(content))
	if err != nil {
		return WriteResult{}, err
	}
	return WriteResult{Path: path, Size: len(content), Changed: changed}, nil
}
