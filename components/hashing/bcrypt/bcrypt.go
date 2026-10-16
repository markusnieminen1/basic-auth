// Package bcrypt is a hashing.PasswordHasher backed by bcrypt (golang.org/x/crypto/bcrypt).
package bcrypt

import (
	"errors"
	"fmt"

	"github.com/markusnieminen1/basic-auth/components/hashing"
	"golang.org/x/crypto/bcrypt"
)

// DefaultCost is the work factor used unless WithCost says otherwise.
// Each step doubles the time one hash takes.
var DefaultCost = 12

type Hasher struct {
	cost int
}

type Option func(*Hasher)

// WithCost sets the bcrypt work factor. New rejects values outside bcrypt's 4..31 range.
func WithCost(cost int) Option {
	return func(h *Hasher) { h.cost = cost }
}

func New(opts ...Option) (*Hasher, error) {
	h := &Hasher{cost: DefaultCost}
	for _, opt := range opts {
		opt(h)
	}
	if h.cost < bcrypt.MinCost || h.cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt: cost %d is outside %d..%d", h.cost, bcrypt.MinCost, bcrypt.MaxCost)
	}
	return h, nil
}

// Hash returns the bcrypt hash. Passwords longer than 72 bytes are rejected with an
// error instead of being silently truncated.
func (h *Hasher) Hash(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), h.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Verify reports whether plain matches hash. A mismatch is (false, nil), while a hash
// that is not a valid bcrypt hash is an error.
func (h *Hasher) Verify(plain, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	return false, err
}

var _ hashing.PasswordHasher = (*Hasher)(nil)
