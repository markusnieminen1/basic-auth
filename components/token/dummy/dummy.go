// Package dummy holds token strategies for development and tests.
//
// NOT FOR PRODUCTION: Access tokens are not signed, so anybody can forge one.
// Refresh is fine to keep, it is a random opaque token hashed with SHA-256.
package dummy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/markusnieminen1/basic-auth/components/token"
)

// Access issues tokens shaped "dummy.<userID>.<expiresUnixNano>.<nonce>". The nonce
// makes every token unique, so revoking one login does not revoke another.
type Access struct{}

func (a *Access) Issue(ctx context.Context, userID int64, ttl time.Duration) (string, time.Time, error) {
	nonce, err := randomHex(8)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().Add(ttl)
	return fmt.Sprintf("dummy.%d.%d.%s", userID, expiresAt.UnixNano(), nonce), expiresAt, nil
}

func (a *Access) Validate(ctx context.Context, rawToken string) (int64, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 4 || parts[0] != "dummy" {
		return 0, token.ErrInvalidToken
	}
	userID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, token.ErrInvalidToken
	}
	expiresNano, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || !time.Now().Before(time.Unix(0, expiresNano)) {
		return 0, token.ErrInvalidToken
	}
	return userID, nil
}

// Refresh issues random opaque tokens. Validity is decided by the session store.
type Refresh struct{}

func (r *Refresh) Issue(ctx context.Context, ttl time.Duration) (string, time.Time, error) {
	raw, err := randomHex(32)
	if err != nil {
		return "", time.Time{}, err
	}
	return raw, time.Now().Add(ttl), nil
}

func (r *Refresh) Hash(rawToken string) (string, error) {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:]), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var (
	_ token.AccessTokenLogic  = (*Access)(nil)
	_ token.RefreshTokenLogic = (*Refresh)(nil)
)

func NewAccess() *Access {
	return &Access{}
}

func NewRefresh() *Refresh {
	return &Refresh{}
}
