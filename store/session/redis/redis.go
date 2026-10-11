package redis

import (
	"context"

	"github.com/markusnieminen1/basic-auth/store/session"
)

type Repo struct{}

func (r *Repo) Create(ctx context.Context, data session.Session) error {
	return nil
}

func (r *Repo) GetByTokenHash(ctx context.Context, token string) (session.Session, error) {
	return session.Session{}, session.ErrNotFound
}

func (r *Repo) Revoke(ctx context.Context, token string) error {
	return nil
}

func (r *Repo) RevokeAllForUser(ctx context.Context, userID int64) error {
	return nil
}

var _ session.Repository = (*Repo)(nil)

func New() *Repo {
	return &Repo{}
}
