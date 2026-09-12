package models

import (
	"context"
	"time"
)

type UserSessionDatabase interface {
	// Sessions
	CreateSession(ctx context.Context, userID int64, refreshToken string, validUntil time.Time) (err error)
	GetSessionByToken(ctx context.Context, refreshToken string) (session *AccessToken, err error)
	RevokeSession(ctx context.Context, refreshToken string) (err error)
	GetAllSessions(ctx context.Context) (session *[]SessionByUsers, err error)
}
