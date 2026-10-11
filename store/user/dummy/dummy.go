// Package dummy is an in-memory user.Repository for development and tests.
// Users are lost on restart and are not shared between processes.
package dummy

import (
	"context"
	"sync"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/store/user"
)

type Repo struct {
	mu     sync.Mutex
	users  map[int64]sharedmodels.AllUserProfileAuthData
	nextID int64
}

func (r *Repo) Create(ctx context.Context, data sharedmodels.AllUserProfileAuthData) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.checkTaken(0, data.Username, data.Email); err != nil {
		return 0, err
	}
	r.nextID++
	data.UserID = r.nextID
	r.users[data.UserID] = data
	return data.UserID, nil
}

func (r *Repo) GetByID(ctx context.Context, userID int64) (sharedmodels.LimitedUserAuthData, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	found, ok := r.users[userID]
	if !ok {
		return sharedmodels.LimitedUserAuthData{}, user.ErrNotFound
	}
	return sharedmodels.LimitedUserAuthData{UserID: found.UserID, Email: found.Email, Username: found.Username}, nil
}

func (r *Repo) GetCredentialsByID(ctx context.Context, userID int64) (sharedmodels.AllUserProfileAuthData, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	found, ok := r.users[userID]
	if !ok {
		return sharedmodels.AllUserProfileAuthData{}, user.ErrNotFound
	}
	return found, nil
}

func (r *Repo) GetByUsername(ctx context.Context, username string) (sharedmodels.AllUserProfileAuthData, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, found := range r.users {
		if found.Username == username {
			return found, nil
		}
	}
	return sharedmodels.AllUserProfileAuthData{}, user.ErrNotFound
}

func (r *Repo) UpdateEmail(ctx context.Context, userID int64, email string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	found, ok := r.users[userID]
	if !ok {
		return user.ErrNotFound
	}
	if err := r.checkTaken(userID, "", email); err != nil {
		return err
	}
	found.Email = email
	r.users[userID] = found
	return nil
}

func (r *Repo) UpdateUsername(ctx context.Context, userID int64, username string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	found, ok := r.users[userID]
	if !ok {
		return user.ErrNotFound
	}
	if err := r.checkTaken(userID, username, ""); err != nil {
		return err
	}
	found.Username = username
	r.users[userID] = found
	return nil
}

func (r *Repo) UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	found, ok := r.users[userID]
	if !ok {
		return user.ErrNotFound
	}
	found.PasswordHash = passwordHash
	r.users[userID] = found
	return nil
}

func (r *Repo) Delete(ctx context.Context, userID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.users[userID]; !ok {
		return user.ErrNotFound
	}
	delete(r.users, userID)
	return nil
}

// checkTaken reports a conflict with any user other than except. Empty values are skipped.
// The caller holds the lock.
func (r *Repo) checkTaken(except int64, username, email string) error {
	for id, other := range r.users {
		if id == except {
			continue
		}
		if username != "" && other.Username == username {
			return user.ErrUsernameTaken
		}
		if email != "" && other.Email == email {
			return user.ErrEmailTaken
		}
	}
	return nil
}

var _ user.Repository = (*Repo)(nil)

func New() *Repo {
	return &Repo{users: make(map[int64]sharedmodels.AllUserProfileAuthData)}
}
