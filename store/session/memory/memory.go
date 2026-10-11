// Package memory is an in-memory session.Repository. Sessions are lost on restart
// and are not shared between processes, so it suits development, tests and single-node setups.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/markusnieminen1/basic-auth/store/session"
)

type Repo struct {
	mu       sync.Mutex
	sessions map[string]session.Session // by refresh token hash
}

func (r *Repo) Create(ctx context.Context, data session.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sessions[data.RefreshTokenHash] = data
	return nil
}

func (r *Repo) GetByTokenHash(ctx context.Context, tokenHash string) (session.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	found, ok := r.sessions[tokenHash]
	if !ok {
		return session.Session{}, session.ErrNotFound
	}
	if !time.Now().Before(found.ValidUntil) {
		delete(r.sessions, tokenHash)
		return session.Session{}, session.ErrNotFound
	}
	return found, nil
}

func (r *Repo) Revoke(ctx context.Context, tokenHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.sessions, tokenHash)
	return nil
}

func (r *Repo) RevokeAllForUser(ctx context.Context, userID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for hash, s := range r.sessions {
		if s.UserID == userID {
			delete(r.sessions, hash)
		}
	}
	return nil
}

var _ session.Repository = (*Repo)(nil)

func New() *Repo {
	return &Repo{sessions: make(map[string]session.Session)}
}
