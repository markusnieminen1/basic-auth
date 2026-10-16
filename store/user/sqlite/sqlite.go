package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/store/user"
)

type Repo struct {
	db *sql.DB
}

func (r *Repo) Create(ctx context.Context, data sharedmodels.AllUserProfileAuthData) (int64, error) {

	result, err := r.db.ExecContext(ctx, `INSERT INTO users (username, email, pwd_hash) VALUES (?, ?, ?)`, data.Username, data.Email, data.PasswordHash)

	if err != nil {
		return 0, mapError(err)
	}

	return result.LastInsertId()
}

func (r *Repo) GetByID(ctx context.Context, userID int64) (data sharedmodels.LimitedUserAuthData, err error) {

	err = r.db.QueryRowContext(ctx, `SELECT user_id, username, email FROM users WHERE user_id = ?`, userID).Scan(&data.UserID, &data.Username, &data.Email)

	return data, mapError(err)
}

func (r *Repo) GetCredentialsByID(ctx context.Context, userID int64) (data sharedmodels.AllUserProfileAuthData, err error) {

	err = r.db.QueryRowContext(ctx, `SELECT user_id, username, email, pwd_hash FROM users WHERE user_id = ?`, userID).Scan(&data.UserID, &data.Username, &data.Email, &data.PasswordHash)

	return data, mapError(err)
}

func (r *Repo) GetByUsername(ctx context.Context, username string) (data sharedmodels.AllUserProfileAuthData, err error) {

	err = r.db.QueryRowContext(ctx, `SELECT user_id, username, email, pwd_hash FROM users WHERE username = ?`, username).Scan(&data.UserID, &data.Username, &data.Email, &data.PasswordHash)

	return data, mapError(err)
}

func (r *Repo) UpdateEmail(ctx context.Context, userID int64, email string) error {
	return r.updateColumn(ctx, "email", email, userID)
}

func (r *Repo) UpdateUsername(ctx context.Context, userID int64, username string) error {
	return r.updateColumn(ctx, "username", username, userID)
}

func (r *Repo) UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	return r.updateColumn(ctx, "pwd_hash", passwordHash, userID)
}

func (r *Repo) Delete(ctx context.Context, userID int64) error {
	tx, err := r.db.BeginTx(ctx, nil)

	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err = tx.ExecContext(ctx, `DELETE FROM user_sessions WHERE user_id = ?`, userID); err != nil {
		return err
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM users WHERE user_id = ?`, userID)

	if err = requireRowAffected(result, err); err != nil {
		return err
	}

	return tx.Commit()
}

// updateColumn sets a single column. The column name is always a constant from this file.
func (r *Repo) updateColumn(ctx context.Context, column string, value any, userID int64) error {

	result, err := r.db.ExecContext(ctx, `UPDATE users SET `+column+` = ? WHERE user_id = ?`, value, userID)

	return requireRowAffected(result, err)
}

func requireRowAffected(result sql.Result, err error) error {

	if err != nil {
		return mapError(err)
	}

	n, err := result.RowsAffected()

	if err != nil {
		return err
	}

	if n == 0 {
		return user.ErrNotFound
	}

	return nil
}

// maps SQL errors to go errors
func mapError(err error) error {

	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return user.ErrNotFound
	case strings.Contains(err.Error(), "UNIQUE constraint failed: users.username"):
		return user.ErrUsernameTaken
	case strings.Contains(err.Error(), "UNIQUE constraint failed: users.email"):
		return user.ErrEmailTaken
	}

	return err
}

var _ user.Repository = (*Repo)(nil)

func New(db *sql.DB) *Repo {
	return &Repo{db: db}
}
