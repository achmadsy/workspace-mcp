package workspace

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/limits"
)

type PatchResult struct {
	FilesChanged int      `json:"files_changed"`
	Paths        []string `json:"paths"`
}

type patchFile struct {
	oldPath string
	newPath string
	hunks   []patchHunk
	content []byte
}

type patchHunk struct {
	oldStart int
	oldCount int
	newStart int
	newCount int
	lines    []patchLine
}

type patchLine struct {
	kind byte
	text string
}

// ApplyPatch parses, validates, and applies a unified text diff. Every file and
// hunk is validated before any workspace mutation starts.
func (r *Root) ApplyPatch(diff string) (PatchResult, error) {
	if diff == "" || int64(len(diff)) > limits.MaxRequestBody || !utf8.ValidString(diff) || strings.IndexByte(diff, 0) >= 0 {
		return PatchResult{}, errors.New("patch is empty, invalid, or exceeds limit")
	}
	files, err := parseUnifiedDiff(diff)
	if err != nil {
		return PatchResult{}, err
	}
	if len(files) == 0 || len(files) > limits.MaxPatchFiles {
		return PatchResult{}, errors.New("patch file count is outside allowed range")
	}

	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	seen := make(map[string]struct{}, len(files))
	for i := range files {
		file := &files[i]
		if file.oldPath == "/dev/null" || file.newPath == "/dev/null" {
			return PatchResult{}, errors.New("patch create/delete operations are not supported")
		}
		if file.oldPath != file.newPath {
			return PatchResult{}, errors.New("patch renames are not supported")
		}
		if err := ValidatePath(file.newPath, false); err != nil {
			return PatchResult{}, err
		}
		if _, ok := seen[file.newPath]; ok {
			return PatchResult{}, errors.New("patch contains duplicate file path")
		}
		seen[file.newPath] = struct{}{}
		current, err := r.Read(file.newPath)
		if err != nil {
			return PatchResult{}, err
		}
		updated, err := applyHunks([]byte(current.Content), file.hunks)
		if err != nil {
			return PatchResult{}, fmt.Errorf("apply %s: %w", file.newPath, err)
		}
		if len(updated) > limits.MaxWriteBytes {
			return PatchResult{}, errors.New("patched file exceeds write limit")
		}
		file.content = updated
	}
	result := PatchResult{Paths: make([]string, 0, len(files))}
	for _, file := range files {
		changed, err := r.atomicWrite(file.newPath, file.content)
		if err != nil {
			return PatchResult{}, err
		}
		if changed {
			result.FilesChanged++
			result.Paths = append(result.Paths, file.newPath)
		}
	}
	return result, nil
}

func parseUnifiedDiff(diff string) ([]patchFile, error) {
	if strings.Contains(diff, "\r") {
		return nil, errors.New("patch must use LF line endings")
	}
	lines := splitPatchLines(diff)
	var files []patchFile
	for i := 0; i < len(lines); {
		if strings.HasPrefix(lines[i], "diff --git ") || strings.HasPrefix(lines[i], "index ") {
			i++
			continue
		}
		if !strings.HasPrefix(lines[i], "--- ") {
			return nil, fmt.Errorf("expected old file header at line %d", i+1)
		}
		oldPath, err := patchPath(strings.TrimPrefix(lines[i], "--- "))
		if err != nil {
			return nil, err
		}
		i++
		if i >= len(lines) || !strings.HasPrefix(lines[i], "+++ ") {
			return nil, errors.New("missing new file header")
		}
		newPath, err := patchPath(strings.TrimPrefix(lines[i], "+++ "))
		if err != nil {
			return nil, err
		}
		i++
		file := patchFile{oldPath: oldPath, newPath: newPath}
		for i < len(lines) && strings.HasPrefix(lines[i], "@@ ") {
			hunk, next, err := parseHunk(lines, i)
			if err != nil {
				return nil, err
			}
			file.hunks = append(file.hunks, hunk)
			i = next
		}
		if len(file.hunks) == 0 {
			return nil, errors.New("file patch has no hunks")
		}
		files = append(files, file)
	}
	return files, nil
}

func patchPath(header string) (string, error) {
	if tab := strings.IndexByte(header, '\t'); tab >= 0 {
		header = header[:tab]
	}
	header = strings.TrimSpace(header)
	if header == "/dev/null" {
		return header, nil
	}
	if strings.HasPrefix(header, "a/") || strings.HasPrefix(header, "b/") {
		header = header[2:]
	}
	if header == "" {
		return "", errors.New("empty patch path")
	}
	return header, nil
}

func parseHunk(lines []string, start int) (patchHunk, int, error) {
	header := lines[start]
	end := strings.Index(header[3:], "@@")
	if end < 0 {
		return patchHunk{}, start, errors.New("invalid hunk header")
	}
	ranges := strings.Fields(header[3 : 3+end])
	if len(ranges) != 2 {
		return patchHunk{}, start, errors.New("invalid hunk ranges")
	}
	oldStart, oldCount, err := parseRange(ranges[0], '-')
	if err != nil {
		return patchHunk{}, start, err
	}
	newStart, newCount, err := parseRange(ranges[1], '+')
	if err != nil {
		return patchHunk{}, start, err
	}
	hunk := patchHunk{oldStart: oldStart, oldCount: oldCount, newStart: newStart, newCount: newCount}
	oldSeen, newSeen := 0, 0
	i := start + 1
	for oldSeen < oldCount || newSeen < newCount {
		if i >= len(lines) {
			return patchHunk{}, start, errors.New("hunk ended before declared line counts")
		}
		line := lines[i]
		if line == `\ No newline at end of file` {
			return patchHunk{}, start, errors.New("patches changing final newline state are not supported")
		}
		if line == "" {
			return patchHunk{}, start, errors.New("unprefixed empty patch line")
		}
		kind := line[0]
		if kind != ' ' && kind != '+' && kind != '-' {
			return patchHunk{}, start, errors.New("invalid hunk line prefix")
		}
		hunk.lines = append(hunk.lines, patchLine{kind: kind, text: line[1:]})
		if kind != '+' {
			oldSeen++
		}
		if kind != '-' {
			newSeen++
		}
		if oldSeen > oldCount || newSeen > newCount {
			return patchHunk{}, start, errors.New("hunk line counts exceed header")
		}
		i++
	}
	if i < len(lines) && lines[i] == `\ No newline at end of file` {
		return patchHunk{}, start, errors.New("patches changing final newline state are not supported")
	}
	return hunk, i, nil
}

func parseRange(value string, prefix byte) (int, int, error) {
	if len(value) < 2 || value[0] != prefix {
		return 0, 0, errors.New("invalid hunk range")
	}
	parts := strings.SplitN(value[1:], ",", 2)
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 0 {
		return 0, 0, errors.New("invalid hunk start")
	}
	count := 1
	if len(parts) == 2 {
		count, err = strconv.Atoi(parts[1])
		if err != nil || count < 0 {
			return 0, 0, errors.New("invalid hunk count")
		}
	}
	return start, count, nil
}

func applyHunks(content []byte, hunks []patchHunk) ([]byte, error) {
	lines, trailing := splitContentLines(content)
	var out []string
	cursor := 0
	for _, hunk := range hunks {
		position := hunkPosition(hunk.oldStart, hunk.oldCount)
		if position < cursor || position > len(lines) {
			return nil, errors.New("hunk position is outside file")
		}
		out = append(out, lines[cursor:position]...)
		newPosition := hunkPosition(hunk.newStart, hunk.newCount)
		if newPosition != len(out) {
			return nil, errors.New("new hunk position does not match output")
		}
		index := position
		for _, line := range hunk.lines {
			switch line.kind {
			case ' ':
				if index >= len(lines) || lines[index] != line.text {
					return nil, errors.New("hunk context does not match")
				}
				out = append(out, line.text)
				index++
			case '-':
				if index >= len(lines) || lines[index] != line.text {
					return nil, errors.New("hunk removal does not match")
				}
				index++
			case '+':
				out = append(out, line.text)
			}
		}
		cursor = index
	}
	out = append(out, lines[cursor:]...)
	result := []byte(strings.Join(out, "\n"))
	if trailing {
		result = append(result, '\n')
	}
	return result, nil
}

// hunkPosition converts a unified-diff start and count into a zero-based line
// index. For a non-empty range the start is the first line of the range; for an
// empty range (count 0, as in `diff -U0` insertions and deletions) the start is
// the line before the change, so the index is the start itself.
func hunkPosition(start, count int) int {
	if count == 0 || start == 0 {
		return start
	}
	return start - 1
}

func splitPatchLines(value string) []string {
	value = strings.TrimSuffix(value, "\n")
	return strings.Split(value, "\n")
}

func splitContentLines(content []byte) ([]string, bool) {
	trailing := bytes.HasSuffix(content, []byte{'\n'})
	value := string(content)
	if trailing {
		value = strings.TrimSuffix(value, "\n")
	}
	if value == "" {
		return nil, trailing
	}
	return strings.Split(value, "\n"), trailing
}
