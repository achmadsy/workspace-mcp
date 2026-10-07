//go:build linux

package git

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/link/workspace-mcp/internal/config"
	"github.com/link/workspace-mcp/internal/sandboxexec"
	"golang.org/x/sys/unix"
)

type credentialBroker struct {
	mode       string
	credential *os.File
	knownHosts *os.File
}

func newCredentialBroker(cfg config.Config) (*credentialBroker, error) {
	broker := &credentialBroker{mode: cfg.GitCredentialMode}
	if !cfg.EnableGitNetwork || cfg.GitCredentialMode == "none" {
		return broker, nil
	}
	credential, err := openCredential(cfg.GitCredentialFile)
	if err != nil {
		return nil, fmt.Errorf("open Git credential: %w", err)
	}
	broker.credential = credential
	if cfg.GitCredentialMode == "https_token" {
		if err := validateTokenContent(credential); err != nil {
			credential.Close()
			return nil, err
		}
	}
	if cfg.GitCredentialMode == "ssh_key" {
		knownHosts, err := openCredential(cfg.GitKnownHostsFile)
		if err != nil {
			credential.Close()
			return nil, fmt.Errorf("open Git known_hosts: %w", err)
		}
		broker.knownHosts = knownHosts
	}
	return broker, nil
}

func (b *credentialBroker) close() {
	if b == nil {
		return
	}
	if b.credential != nil {
		_ = b.credential.Close()
	}
	if b.knownHosts != nil {
		_ = b.knownHosts.Close()
	}
}

func (b *credentialBroker) filesForURL(raw string) (sandboxexec.GitCredentialFiles, func(), error) {
	if b == nil || b.mode == "none" {
		return sandboxexec.GitCredentialFiles{}, func() {}, nil
	}
	isSSH := strings.HasPrefix(raw, "git@") || strings.HasPrefix(raw, "ssh://")
	isHTTPS := strings.HasPrefix(raw, "https://")
	switch b.mode {
	case "ssh_key":
		if !isSSH {
			return sandboxexec.GitCredentialFiles{}, nil, errors.New("SSH credentials require an SSH remote URL")
		}
		key, err := duplicateCredential(b.credential)
		if err != nil {
			return sandboxexec.GitCredentialFiles{}, nil, err
		}
		knownHosts, err := duplicateCredential(b.knownHosts)
		if err != nil {
			key.Close()
			return sandboxexec.GitCredentialFiles{}, nil, err
		}
		return sandboxexec.GitCredentialFiles{SSHKey: key, KnownHosts: knownHosts}, func() {
			key.Close()
			knownHosts.Close()
		}, nil
	case "https_token":
		if !isHTTPS {
			return sandboxexec.GitCredentialFiles{}, nil, errors.New("HTTPS token requires an HTTPS remote URL")
		}
		token, err := duplicateCredential(b.credential)
		if err != nil {
			return sandboxexec.GitCredentialFiles{}, nil, err
		}
		return sandboxexec.GitCredentialFiles{HTTPSToken: token}, func() { token.Close() }, nil
	default:
		return sandboxexec.GitCredentialFiles{}, nil, errors.New("unsupported Git credential mode")
	}
}

func validateTokenContent(file *os.File) error {
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	content, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	content = bytes.TrimSuffix(content, []byte{'\n'})
	if len(content) == 0 || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 || bytes.ContainsAny(content, "\r\n") {
		return errors.New("HTTPS token must be one non-empty UTF-8 line")
	}
	return nil
}

func openCredential(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "git-credential")
	if err := validateCredentialDescriptor(fd); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func duplicateCredential(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, errors.New("Git credential descriptor is unavailable")
	}
	// Opening the retained inode through procfs creates an independent file
	// description. dup(2) would share an offset across concurrent operations.
	path := fmt.Sprintf("/proc/self/fd/%d", source.Fd())
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "git-credential-operation")
	if err := validateCredentialDescriptor(fd); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validateCredentialDescriptor(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 || st.Nlink != 1 || int(st.Uid) != os.Getuid() {
		return errors.New("credential must be owner-only, regular, single-linked, and owned by server user")
	}
	if st.Size <= 0 || st.Size > 1<<20 {
		return errors.New("credential file size is outside allowed range")
	}
	return nil
}
