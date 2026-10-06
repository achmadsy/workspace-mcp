package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Client struct {
	ClientID     string    `json:"client_id"`
	ClientName   string    `json:"client_name"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}
type PendingAuthorization struct {
	ID, ClientID, RedirectURI, Resource, Scope, State, CodeChallenge string
	CreatedAt, ExpiresAt                                             time.Time
}
type CodeGrant struct {
	Hash, ClientID, RedirectURI, Resource, Scope, CodeChallenge string
	ExpiresAt                                                   time.Time
}
type BrowserSession struct {
	Hash, CSRF                     string
	Authenticated                  bool
	CreatedAt, LastSeen, ExpiresAt time.Time
}
type TokenRecord struct {
	Hash, ClientID, Resource, Scope, Family string
	ExpiresAt                               time.Time
}
type RefreshRecord struct {
	Hash, ClientID, Resource, Scope, Family string
	ExpiresAt                               time.Time
	Used                                    bool
}

type state struct {
	Version         int                             `json:"version"`
	PublicURL       string                          `json:"public_url"`
	Clients         map[string]Client               `json:"clients"`
	Pending         map[string]PendingAuthorization `json:"pending"`
	Codes           map[string]CodeGrant            `json:"codes"`
	Sessions        map[string]BrowserSession       `json:"sessions"`
	Access          map[string]TokenRecord          `json:"access"`
	Refresh         map[string]RefreshRecord        `json:"refresh"`
	RevokedFamilies map[string]bool                 `json:"revoked_families"`
	Consents        map[string]bool                 `json:"consents"`
}

type Store struct {
	mu                   sync.Mutex
	dir, path, publicURL string
	key                  [32]byte
	lock                 *os.File
	data                 state
}

func OpenStore(dir string, key [32]byte, publicURL string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure state directory: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("OAuth state is already in use by another process")
	}
	s := &Store{dir: dir, path: filepath.Join(dir, "state.enc"), publicURL: publicURL, key: key, lock: lock}
	s.data = emptyState(publicURL)
	if raw, err := os.ReadFile(s.path); err == nil {
		var env envelope
		if json.Unmarshal(raw, &env) != nil {
			s.Close()
			return nil, errors.New("encrypted OAuth state is corrupt")
		}
		plain, err := decrypt(key, env)
		if err != nil {
			s.Close()
			return nil, err
		}
		if json.Unmarshal(plain, &s.data) != nil || s.data.Version != 1 {
			s.Close()
			return nil, errors.New("OAuth state is invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		s.Close()
		return nil, err
	}
	if s.data.PublicURL != publicURL {
		s.data = emptyState(publicURL)
		if err := s.saveLocked(); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

func emptyState(u string) state {
	return state{Version: 1, PublicURL: u, Clients: map[string]Client{}, Pending: map[string]PendingAuthorization{}, Codes: map[string]CodeGrant{}, Sessions: map[string]BrowserSession{}, Access: map[string]TokenRecord{}, Refresh: map[string]RefreshRecord{}, RevokedFamilies: map[string]bool{}, Consents: map[string]bool{}}
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
	err := s.lock.Close()
	s.lock = nil
	return err
}
func (s *Store) saveLocked() error {
	plain, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	env, err := encrypt(s.key, plain)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	tmp, err := os.OpenFile(filepath.Join(s.dir, ".state.tmp"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err = tmp.Write(raw); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	ok = true
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (s *Store) update(fn func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.data); err != nil {
		return err
	}
	return s.saveLocked()
}
func (s *Store) view(fn func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&s.data)
}
