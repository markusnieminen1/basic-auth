// Package dummy is a PasswordHasher for development and tests.
//
// NOT FOR PRODUCTION: it is an unsalted SHA-256, which is fast to brute force.
// Use a real password hash (bcrypt, argon2) outside of tests.
package dummy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"

	"github.com/markusnieminen1/basic-auth/components/hashing"
)

const prefix = "dummy$"

type Hasher struct{}

func (h *Hasher) Hash(plain string) (string, error) {
	sum := sha256.Sum256([]byte(plain))
	return prefix + hex.EncodeToString(sum[:]), nil
}

func (h *Hasher) Verify(plain, hash string) (bool, error) {
	expected, err := h.Hash(plain)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(hash)) == 1, nil
}

var _ hashing.PasswordHasher = (*Hasher)(nil)

func New() *Hasher {
	return &Hasher{}
}
