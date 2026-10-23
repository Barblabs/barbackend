// Package encryption seals CMDB Source credentials with AES-256-GCM (ADR
// 0012). It is the only package that encrypts or decrypts: callers pass the
// key and sealed bytes through without reading them.
package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	keySize   = 32
	keyIDSize = 8
)

var (
	ErrInvalidKey = errors.New("invalid encryption key")
	ErrNoKey      = errors.New("encryption key is not set")
	ErrWrongKey   = errors.New("sealed with another encryption key")
	ErrCorrupt    = errors.New("sealed data is corrupt")
)

// Key is an AES-256 key and its id. Only ParseKey makes a usable one; the
// zero Key fails every Seal and Open with ErrNoKey rather than panicking.
type Key struct {
	id   []byte
	aead cipher.AEAD
}

// ParseKey reads a base64-encoded 32-byte key, as printed by
// `openssl rand -base64 32`.
func ParseKey(encoded string) (Key, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Key{}, fmt.Errorf("%w: not base64: %v", ErrInvalidKey, err)
	}
	if len(raw) != keySize {
		return Key{}, fmt.Errorf("%w: %d bytes, want %d", ErrInvalidKey, len(raw), keySize)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return Key{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Key{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return Key{id: keyID(raw), aead: aead}, nil
}

// keyID is derived from the key rather than configured, so two keys can
// never share an id. A truncated SHA-256 of a random 256-bit key reveals
// nothing usable about it.
func keyID(raw []byte) []byte {
	sum := sha256.Sum256(append([]byte("barbackend encryption key id\x00"), raw...))
	return sum[:keyIDSize]
}

// Seal encrypts plaintext into key id | nonce | ciphertext. The key id and
// owner (such as a CMDB Source id) are authenticated with it, so the
// ciphertext cannot be moved to another owner.
func (k Key) Seal(plaintext, owner []byte) ([]byte, error) {
	if k.aead == nil {
		return nil, ErrNoKey
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	out := append(bytes.Clone(k.id), nonce...)
	return k.aead.Seal(out, nonce, plaintext, k.authenticatedData(owner)), nil
}

// Open decrypts what Seal returned for the same owner.
func (k Key) Open(sealed, owner []byte) ([]byte, error) {
	if k.aead == nil {
		return nil, ErrNoKey
	}
	header := keyIDSize + k.aead.NonceSize()
	if len(sealed) < header+k.aead.Overhead() {
		return nil, fmt.Errorf("%w: %d bytes is too short", ErrCorrupt, len(sealed))
	}
	if id := sealed[:keyIDSize]; !bytes.Equal(id, k.id) {
		return nil, fmt.Errorf("%w: key id %s, the encryption key is %s", ErrWrongKey, hex.EncodeToString(id), hex.EncodeToString(k.id))
	}
	plaintext, err := k.aead.Open(nil, sealed[keyIDSize:header], sealed[header:], k.authenticatedData(owner))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return plaintext, nil
}

// authenticatedData starts with the fixed-size key id, so no key id and owner
// pair can collide with another.
func (k Key) authenticatedData(owner []byte) []byte {
	return append(bytes.Clone(k.id), owner...)
}
