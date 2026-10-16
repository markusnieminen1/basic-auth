package token

import (
	"context"
	"errors"
	"time"
)

// ErrInvalidToken must be returned by AccessTokenLogic.Validate for any token that is
// malformed, forged or expired, so callers can tell it apart from an internal failure.
var ErrInvalidToken = errors.New("invalid token")

// AccessTokenLogic issues and validates short-lived access tokens
type AccessTokenLogic interface {
	Issue(ctx context.Context, userID int64, ttl time.Duration) (token string, expiresAt time.Time, err error)
	Validate(ctx context.Context, token string) (userID int64, err error)
}

// RefreshTokenLogic generates long-lived refresh tokens and hashes them for storage.
// The session store is the source of truth for whether a token is valid
type RefreshTokenLogic interface {
	Issue(ctx context.Context, ttl time.Duration) (token string, expiresAt time.Time, err error)
	Hash(token string) (string, error)
}
