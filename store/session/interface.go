package session

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by GetByTokenHash when no session matches or it has expired.
var ErrNotFound = errors.New("session not found")

type Session struct {
	UserID           int64
	RefreshTokenHash string
	ValidUntil       time.Time
}

// Repository stores one session per refresh token (one per device login).
type Repository interface {
	Create(ctx context.Context, session Session) error
	// GetByTokenHash returns ErrNotFound for unknown and for expired sessions.
	GetByTokenHash(ctx context.Context, tokenHash string) (Session, error)
	// Revoke and RevokeAllForUser are idempotent: revoking nothing is not an error.
	Revoke(ctx context.Context, tokenHash string) error
	RevokeAllForUser(ctx context.Context, userID int64) error
}
