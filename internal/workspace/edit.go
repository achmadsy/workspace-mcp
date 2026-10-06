package workspace

import (
	"bytes"
	"errors"
)

type EditResult struct {
	Path    string `json:"path"`
	Size    int    `json:"size"`
	Changed bool   `json:"changed"`
}

func (r *Root) Edit(path, oldText, newText string) (EditResult, error) {
	if oldText == "" {
		return EditResult{}, errors.New("old_text must not be empty")
	}
	if bytes.IndexByte([]byte(newText), 0) >= 0 {
		return EditResult{}, errors.New("new_text must not contain NUL bytes")
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	current, err := r.Read(path)
	if err != nil {
		return EditResult{}, err
	}
	count := bytes.Count([]byte(current.Content), []byte(oldText))
	if count == 0 {
		return EditResult{}, errors.New("old_text was not found")
	}
	if count != 1 {
		return EditResult{}, errors.New("old_text must occur exactly once")
	}
	updated := bytes.Replace([]byte(current.Content), []byte(oldText), []byte(newText), 1)
	changed, err := r.atomicWrite(path, updated)
	if err != nil {
		return EditResult{}, err
	}
	return EditResult{Path: path, Size: len(updated), Changed: changed}, nil
}
