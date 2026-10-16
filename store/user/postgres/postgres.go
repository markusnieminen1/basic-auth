package postgres

import (
	"context"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/store/database"
	"github.com/markusnieminen1/basic-auth/store/user"
)

// Repo is a not-yet-implemented placeholder. Every method returns database.ErrNotImplemented
// instead of pretending to work. TODO: implement.
type Repo struct{}

func (r *Repo) Create(ctx context.Context, userData sharedmodels.AllUserProfileAuthData) (int64, error) {
	return 0, database.ErrNotImplemented
}

func (r *Repo) GetByID(ctx context.Context, userID int64) (sharedmodels.LimitedUserAuthData, error) {
	return sharedmodels.LimitedUserAuthData{}, database.ErrNotImplemented
}

func (r *Repo) GetCredentialsByID(ctx context.Context, userID int64) (sharedmodels.AllUserProfileAuthData, error) {
	return sharedmodels.AllUserProfileAuthData{}, database.ErrNotImplemented
}

func (r *Repo) GetByUsername(ctx context.Context, username string) (sharedmodels.AllUserProfileAuthData, error) {
	return sharedmodels.AllUserProfileAuthData{}, database.ErrNotImplemented
}

func (r *Repo) UpdateEmail(ctx context.Context, userID int64, email string) error {
	return database.ErrNotImplemented
}

func (r *Repo) UpdateUsername(ctx context.Context, userID int64, username string) error {
	return database.ErrNotImplemented
}

func (r *Repo) UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	return database.ErrNotImplemented
}

func (r *Repo) Delete(ctx context.Context, userID int64) error {
	return database.ErrNotImplemented
}

var _ user.Repository = (*Repo)(nil)

func New() *Repo {
	return &Repo{}
}
