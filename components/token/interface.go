package token

import (
	"context"
	"errors"
	"time"
)

// ErrInvalidToken must be returned by AccessStrategy.Validate for any token that is
// malformed, forged or expired, so callers can tell it apart from an internal failure.
var ErrInvalidToken = errors.New("invalid token")

// AccessStrategy issues and validates short-lived access tokens (JWT, PASETO, opaque, ...).
// The strategy owns the expiry, so it can embed it in the token (e.g. the JWT exp claim)
// and report the very same time back to the caller.
type AccessStrategy interface {
	Issue(ctx context.Context, userID int64, ttl time.Duration) (token string, expiresAt time.Time, err error)
	// Validate returns the user ID the token was issued for, or ErrInvalidToken.
	Validate(ctx context.Context, token string) (userID int64, err error)
}

// RefreshStrategy generates long-lived refresh tokens and hashes them for storage.
//
// There is no Validate: the session store is the source of truth for whether a
// refresh token is valid, and the session record tells which user it belongs to.
type RefreshStrategy interface {
	Issue(ctx context.Context, ttl time.Duration) (token string, expiresAt time.Time, err error)
	// Hash must be deterministic: the same token always gives the same hash,
	// because the hash is what the session store looks sessions up by.
	Hash(token string) (string, error)
}
