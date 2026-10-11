package postgres

import (
	"context"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/store/user"
)

// Repo is a not-yet-implemented placeholder. Every lookup reports user.ErrNotFound,
// so nobody can log in through it. TODO: implement.
type Repo struct{}

func (r *Repo) Create(ctx context.Context, userData sharedmodels.AllUserProfileAuthData) (int64, error) {
	return 1, nil
}

func (r *Repo) GetByID(ctx context.Context, userID int64) (sharedmodels.LimitedUserAuthData, error) {
	return sharedmodels.LimitedUserAuthData{}, user.ErrNotFound
}

func (r *Repo) GetCredentialsByID(ctx context.Context, userID int64) (sharedmodels.AllUserProfileAuthData, error) {
	return sharedmodels.AllUserProfileAuthData{}, user.ErrNotFound
}

func (r *Repo) GetByUsername(ctx context.Context, username string) (sharedmodels.AllUserProfileAuthData, error) {
	return sharedmodels.AllUserProfileAuthData{}, user.ErrNotFound
}

func (r *Repo) UpdateEmail(ctx context.Context, userID int64, email string) error {
	return user.ErrNotFound
}

func (r *Repo) UpdateUsername(ctx context.Context, userID int64, username string) error {
	return user.ErrNotFound
}

func (r *Repo) UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	return user.ErrNotFound
}

func (r *Repo) Delete(ctx context.Context, userID int64) error {
	return user.ErrNotFound
}

var _ user.Repository = (*Repo)(nil)

func New() *Repo {
	return &Repo{}
}
