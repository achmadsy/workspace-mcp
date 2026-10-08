//go:build linux

package git

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/link/workspace-mcp/internal/config"
)

func TestCredentialBrokerHTTPS(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	broker, err := newCredentialBroker(config.Config{
		EnableGitNetwork: true, GitCredentialMode: "https_token", GitCredentialFile: tokenPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.close()
	files, cleanup, err := broker.filesForURL("https://example.com/repo.git")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if files.HTTPSToken == nil || files.SSHKey != nil || files.KnownHosts != nil {
		t.Fatalf("unexpected files: %#v", files)
	}
	if _, _, err := broker.filesForURL("git@example.com:repo.git"); err == nil {
		t.Fatal("HTTPS token accepted for SSH URL")
	}
}

func TestCredentialBrokerSSH(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id")
	knownHostsPath := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(keyPath, []byte("private-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHostsPath, []byte("example.com ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	broker, err := newCredentialBroker(config.Config{
		EnableGitNetwork: true, GitCredentialMode: "ssh_key", GitCredentialFile: keyPath, GitKnownHostsFile: knownHostsPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.close()
	files, cleanup, err := broker.filesForURL("git@example.com:repo.git")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if files.SSHKey == nil || files.KnownHosts == nil || files.HTTPSToken != nil {
		t.Fatalf("unexpected files: %#v", files)
	}
	if _, _, err := broker.filesForURL("https://example.com/repo.git"); err == nil {
		t.Fatal("SSH key accepted for HTTPS URL")
	}
}

func TestCredentialBrokerRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the umask; chmod makes the mode explicit.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newCredentialBroker(config.Config{
		EnableGitNetwork: true, GitCredentialMode: "https_token", GitCredentialFile: path,
	}); err == nil {
		t.Fatal("world-readable credential accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(dir, "second-link")); err == nil {
		if _, err := newCredentialBroker(config.Config{
			EnableGitNetwork: true, GitCredentialMode: "https_token", GitCredentialFile: path,
		}); err == nil {
			t.Fatal("multiply-linked credential accepted")
		}
	}
}

func TestCredentialBrokerKeepsOriginalDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	broker, err := newCredentialBroker(config.Config{
		EnableGitNetwork: true, GitCredentialMode: "https_token", GitCredentialFile: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.close()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, cleanup, err := broker.filesForURL("https://example.com/repo.git")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	content, err := os.ReadFile("/proc/self/fd/" + fileDescriptor(files.HTTPSToken))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "first" {
		t.Fatalf("credential descriptor was redirected: %q", content)
	}
}

func fileDescriptor(file *os.File) string {
	return fmt.Sprint(file.Fd())
}
