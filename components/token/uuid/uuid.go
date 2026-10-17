// Package uuid satisfies token.RefreshTokenLogic with UUIDv4 refresh tokens (version 4).
// Plain tokens for browser, SHA-256 tokens to the DB.
package uuid

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/markusnieminen1/basic-auth/components/token"
)

// https://www.rfc-editor.org/info/rfc9562/
// https://github.com/google/uuid/tree/master

// Refresh issues a new UUID for every login and every renewal.
type Refresh struct{}

func (r *Refresh) Issue(ctx context.Context, ttl time.Duration) (string, time.Time, error) {

	id, err := NewUUIDToken()
	if err != nil {
		return "", time.Time{}, err
	}

	return id, time.Now().Add(ttl), nil
}

func (r *Refresh) Hash(rawToken string) (string, error) {
	sum := sha256.Sum256([]byte(rawToken))

	return hex.EncodeToString(sum[:]), nil
}

func NewUUIDToken() (string, error) {

	b := make([]byte, 16)

	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}

	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // variant 10

	var out [36]byte

	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:], b[10:])

	return string(out[:]), nil
}

var _ token.RefreshTokenLogic = (*Refresh)(nil)

func NewRefresh() *Refresh {
	return &Refresh{}
}
