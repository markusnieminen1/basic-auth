package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/markusnieminen1/basic-auth/store/session"
)

type Repo struct {
	db *sql.DB
}

func (r *Repo) Create(ctx context.Context, data session.Session) error {

	_, err := r.db.ExecContext(ctx, `INSERT INTO user_sessions (user_id, refresh_token, valid_until) VALUES (?, ?, ?)`, data.UserID, data.RefreshTokenHash, data.ValidUntil.UTC().Format(time.RFC3339Nano))

	return err
}

func (r *Repo) GetByTokenHash(ctx context.Context, token string) (session.Session, error) {

	var userID int64
	var validUntil string

	err := r.db.QueryRowContext(ctx, `SELECT user_id, valid_until FROM user_sessions WHERE refresh_token = ?`, token).Scan(&userID, &validUntil)

	if errors.Is(err, sql.ErrNoRows) {
		return session.Session{}, session.ErrNotFound
	}

	if err != nil {
		return session.Session{}, err
	}

	parsed, err := time.Parse(time.RFC3339Nano, validUntil)

	if err != nil {
		return session.Session{}, err
	}

	if !parsed.After(time.Now()) {
		return session.Session{}, session.ErrNotFound
	}

	return session.Session{UserID: userID, RefreshTokenHash: token, ValidUntil: parsed}, nil
}

// Revoke is atomic: a single DELETE statement removes the row for exactly one caller.
func (r *Repo) Revoke(ctx context.Context, token string) (bool, error) {

	result, err := r.db.ExecContext(ctx, `DELETE FROM user_sessions WHERE refresh_token = ?`, token)

	if err != nil {
		return false, err
	}

	n, err := result.RowsAffected()

	return n > 0, err
}

func (r *Repo) RevokeAllForUser(ctx context.Context, userID int64) error {

	_, err := r.db.ExecContext(ctx, `DELETE FROM user_sessions WHERE user_id = ?`, userID)

	return err
}

var _ session.Repository = (*Repo)(nil)

func New(db *sql.DB) *Repo {
	return &Repo{db: db}
}
