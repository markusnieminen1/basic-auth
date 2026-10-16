package session

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("session not found")

type Session struct {
	UserID           int64
	RefreshTokenHash string
	ValidUntil       time.Time
}

type Repository interface {
	Create(ctx context.Context, session Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (Session, error)
	Revoke(ctx context.Context, tokenHash string) (revoked bool, err error)
	RevokeAllForUser(ctx context.Context, userID int64) error
}
