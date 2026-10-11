package user

import (
	"context"
	"errors"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
)

// Errors every Repository implementation must return, so the service can tell
// "no such user" or "already taken" apart from "the database is down".
// Implementations must not leak driver errors such as sql.ErrNoRows for these cases.
var (
	ErrNotFound      = errors.New("user not found")
	ErrUsernameTaken = errors.New("username already taken")
	ErrEmailTaken    = errors.New("email already taken")
)

// Repository stores users. The password is only ever seen as a hash.
type Repository interface {
	// Create returns the new user's ID. ErrUsernameTaken / ErrEmailTaken on conflict.
	Create(ctx context.Context, user sharedmodels.AllUserProfileAuthData) (userID int64, err error)
	// GetByID returns the public profile. ErrNotFound if missing.
	GetByID(ctx context.Context, userID int64) (sharedmodels.LimitedUserAuthData, error)
	// GetCredentialsByID returns the profile with the password hash. ErrNotFound if missing.
	GetCredentialsByID(ctx context.Context, userID int64) (sharedmodels.AllUserProfileAuthData, error)
	// GetByUsername returns the profile with the password hash. ErrNotFound if missing.
	GetByUsername(ctx context.Context, username string) (sharedmodels.AllUserProfileAuthData, error)

	// The Update methods return ErrNotFound if the user does not exist.
	UpdateEmail(ctx context.Context, userID int64, email string) error       // ErrEmailTaken on conflict
	UpdateUsername(ctx context.Context, userID int64, username string) error // ErrUsernameTaken on conflict
	UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error

	// Delete returns ErrNotFound if the user does not exist.
	Delete(ctx context.Context, userID int64) error
}
