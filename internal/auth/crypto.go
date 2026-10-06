package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

type envelope struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

func encrypt(key [32]byte, plaintext []byte) (envelope, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return envelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return envelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return envelope{}, err
	}
	data := gcm.Seal(nil, nonce, plaintext, []byte("workspace-mcp-state-v1"))
	return envelope{Version: 1, Nonce: base64.RawStdEncoding.EncodeToString(nonce), Data: base64.RawStdEncoding.EncodeToString(data)}, nil
}

func decrypt(key [32]byte, e envelope) ([]byte, error) {
	if e.Version != 1 {
		return nil, errors.New("unsupported encrypted state version")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return nil, errors.New("invalid encrypted state")
	}
	data, err := base64.RawStdEncoding.DecodeString(e.Data)
	if err != nil {
		return nil, errors.New("invalid encrypted state")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out, err := gcm.Open(nil, nonce, data, []byte("workspace-mcp-state-v1"))
	if err != nil {
		return nil, errors.New("encrypted state authentication failed")
	}
	return out, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hashToken(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
