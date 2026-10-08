package server

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestMutatingWorkspaceToolsAreAudited drives every mutating workspace tool through
// the real server and checks that each call leaves an audit entry that names the
// tool and path but never contains file, edit or patch text.
func TestMutatingWorkspaceToolsAreAudited(t *testing.T) {
	// Not parallel: it swaps the process-wide default logger.
	var logs lockedBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	base, _ := startTestServer(t)

	const (
		contentSecret = "CONTENTSECRET"
		editSecret    = "EDITSECRET"
		patchSecret   = "PATCHSECRET"
	)
	patch := "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,2 +1,2 @@\n " + editSecret + "\n-two-" + contentSecret + "\n+" + patchSecret + "\n"
	calls := []struct {
		tool string
		args map[string]any
	}{
		{"workspace_mkdir", map[string]any{"path": "sub", "parents": true}},
		{"workspace_write", map[string]any{"path": "notes.txt", "content": "one\ntwo-" + contentSecret + "\n"}},
		{"workspace_edit", map[string]any{"path": "notes.txt", "old_text": "one", "new_text": editSecret}},
		{"workspace_copy", map[string]any{"source": "notes.txt", "destination": "sub/copy.txt"}},
		{"workspace_move", map[string]any{"source": "sub/copy.txt", "destination": "sub/moved.txt"}},
		// The patch outcome does not matter here: failed calls are audited too.
		{"workspace_apply_patch", map[string]any{"patch": patch}},
		{"workspace_delete", map[string]any{"path": "sub", "recursive": true}},
	}
	for i, c := range calls {
		out := rpc(t, base, "audit-"+c.tool+"-"+string(rune('a'+i)), "tools/call", map[string]any{"name": c.tool, "arguments": c.args})
		if out["error"] != nil {
			t.Fatalf("%s protocol error: %v", c.tool, out["error"])
		}
	}

	got := logs.String()
	for _, c := range calls {
		if !strings.Contains(got, "tool="+c.tool) {
			t.Errorf("no audit entry for %s in:\n%s", c.tool, got)
		}
	}
	if !strings.Contains(got, "client_id=local") || !strings.Contains(got, "path=notes.txt") {
		t.Errorf("audit entries lack client_id or path:\n%s", got)
	}
	for _, secret := range []string{contentSecret, editSecret, patchSecret} {
		if strings.Contains(got, secret) {
			t.Errorf("audit log leaked %q:\n%s", secret, got)
		}
	}
}
