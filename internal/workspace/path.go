package workspace

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/limits"
)

var ErrUnsafePath = errors.New("unsafe workspace path")

// ValidatePath accepts only normalized, relative, slash-separated paths.
// allowEmpty permits the workspace root for traversal operations.
func ValidatePath(p string, allowEmpty bool) error {
	if p == "" {
		if allowEmpty {
			return nil
		}
		return ErrUnsafePath
	}
	if len(p) > limits.MaxPathBytes || !utf8.ValidString(p) || strings.IndexByte(p, 0) >= 0 || strings.Contains(p, `\`) {
		return ErrUnsafePath
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") {
		return ErrUnsafePath
	}
	parts := strings.Split(p, "/")
	if len(parts) > limits.MaxParentDepth {
		return ErrUnsafePath
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > limits.MaxPathComponent {
			return ErrUnsafePath
		}
		if i == 0 && len(part) >= 2 && part[1] == ':' {
			return ErrUnsafePath
		}
		if part == ".git" {
			return errors.New(".git is reserved")
		}
	}
	return nil
}

func ignoredDirectory(name string) bool {
	switch name {
	case "node_modules", "vendor", ".venv", "target", "dist", "build":
		return true
	}
	return false
}
