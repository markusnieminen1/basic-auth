package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/markusnieminen1/basic-auth/components/hashing"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/internal/validating"
	"github.com/markusnieminen1/basic-auth/store/session"
	"github.com/markusnieminen1/basic-auth/store/user"
)

type AccountManagerService struct {
	validator validating.UserDataValidator
	users     user.Repository
	sessions  session.Repository
	hasher    hashing.PasswordHasher
}

// NewAccountManagerService wires the account service. Everything is required.
// Sessions are needed to end them when the password changes or the account is deleted.
func NewAccountManagerService(users user.Repository, sessions session.Repository, hasher hashing.PasswordHasher) (*AccountManagerService, error) {
	if users == nil {
		return nil, fmt.Errorf("%w: user repository", ErrMissingDependency)
	}
	if sessions == nil {
		return nil, fmt.Errorf("%w: session repository", ErrMissingDependency)
	}
	if hasher == nil {
		return nil, fmt.Errorf("%w: password hasher", ErrMissingDependency)
	}
	return &AccountManagerService{
		validator: validating.NewUserValidatorDefaultSetup(),
		users:     users,
		sessions:  sessions,
		hasher:    hasher,
	}, nil
}

func (u *AccountManagerService) Register(ctx context.Context, input sharedmodels.RegisterInput) (sharedmodels.LimitedUserAuthData, error) {
	// The validator ignores surrounding spaces, so they must not reach the database.
	input.Email = strings.TrimSpace(input.Email)
	input.Username = strings.TrimSpace(input.Username)

	if err := u.validator.ValidateEmail(input.Email); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	if err := u.validator.ValidatePassword(input.Password); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	if err := u.validator.ValidateUsername(input.Username); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}

	passwordHash, err := u.hasher.Hash(input.Password)
	if err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	userID, err := u.users.Create(ctx, sharedmodels.AllUserProfileAuthData{
		Email:        input.Email,
		Username:     input.Username,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	return u.GetByID(ctx, userID)
}

func (u *AccountManagerService) GetByID(ctx context.Context, userID int64) (sharedmodels.LimitedUserAuthData, error) {
	if err := u.validator.ValidateUserID(userID); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	return u.users.GetByID(ctx, userID)
}

func (u *AccountManagerService) UpdateEmail(ctx context.Context, input sharedmodels.UpdateEmailInput) (sharedmodels.LimitedUserAuthData, error) {
	input.Email = strings.TrimSpace(input.Email)
	if err := u.validator.ValidateUserID(input.UserID); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	if err := u.validator.ValidateEmail(input.Email); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	if err := u.verifyPassword(ctx, input.UserID, input.Password); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	if err := u.users.UpdateEmail(ctx, input.UserID, input.Email); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	return u.GetByID(ctx, input.UserID)
}

func (u *AccountManagerService) UpdateUsername(ctx context.Context, input sharedmodels.UpdateUsernameInput) (sharedmodels.LimitedUserAuthData, error) {
	input.Username = strings.TrimSpace(input.Username)
	if err := u.validator.ValidateUserID(input.UserID); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	if err := u.validator.ValidateUsername(input.Username); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	if err := u.verifyPassword(ctx, input.UserID, input.Password); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	if err := u.users.UpdateUsername(ctx, input.UserID, input.Username); err != nil {
		return sharedmodels.LimitedUserAuthData{}, err
	}
	return u.GetByID(ctx, input.UserID)
}

func (u *AccountManagerService) ChangePassword(ctx context.Context, input sharedmodels.ChangePasswordInput) error {
	if err := u.validator.ValidateUserID(input.UserID); err != nil {
		return err
	}
	if err := u.validator.ValidatePassword(input.Replacement); err != nil {
		return err
	}

	if err := u.verifyPassword(ctx, input.UserID, input.Current); err != nil {
		return err
	}
	newHash, err := u.hasher.Hash(input.Replacement)
	if err != nil {
		return err
	}
	if err = u.users.UpdatePasswordHash(ctx, input.UserID, newHash); err != nil {
		return err
	}
	// Whoever knew the old password, or held a session made with it, is signed out everywhere.
	// This runs after the update: if it fails, the caller is told that the password did change.
	if err = u.sessions.RevokeAllForUser(ctx, input.UserID); err != nil {
		return fmt.Errorf("password changed, but ending existing sessions failed: %w", err)
	}
	return nil
}

// verifyPassword checks the user's current password. Account information can only be
// changed by someone who both holds a valid token and knows the password.
func (u *AccountManagerService) verifyPassword(ctx context.Context, userID int64, plain string) error {
	creds, err := u.users.GetCredentialsByID(ctx, userID)
	if err != nil {
		return err
	}
	valid, err := u.hasher.Verify(plain, creds.PasswordHash)
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidCredentials
	}
	return nil
}

func (u *AccountManagerService) Delete(ctx context.Context, userID int64) error {
	if err := u.validator.ValidateUserID(userID); err != nil {
		return err
	}
	// Sessions go first: if deleting the user then fails, the user is merely signed out,
	// whereas the other order could leave live sessions for an account that no longer exists.
	if err := u.sessions.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return u.users.Delete(ctx, userID)
}

var _ AccountService = (*AccountManagerService)(nil)
