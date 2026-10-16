package service

import (
	"context"
	"errors"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
)

// ErrMissingDependency is returned by the service constructors when a required
// component (hasher, repository, token strategy...) was not provided.
var ErrMissingDependency = errors.New("missing required dependency")

// AccountService manages user accounts.
type AccountService interface {
	Register(ctx context.Context, input sharedmodels.RegisterInput) (sharedmodels.LimitedUserAuthData, error)
	GetByID(ctx context.Context, userID int64) (sharedmodels.LimitedUserAuthData, error)
	UpdateEmail(ctx context.Context, input sharedmodels.UpdateEmailInput) (sharedmodels.LimitedUserAuthData, error)
	UpdateUsername(ctx context.Context, input sharedmodels.UpdateUsernameInput) (sharedmodels.LimitedUserAuthData, error)
	ChangePassword(ctx context.Context, input sharedmodels.ChangePasswordInput) error
	Delete(ctx context.Context, userID int64) error
}

// AuthenticationService handles the login / logout lifecycle.
type AuthenticationService interface {
	Login(ctx context.Context, input sharedmodels.LoginInput) (sharedmodels.AuthCookies, error)
	Refresh(ctx context.Context, cookies sharedmodels.AuthCookies) (sharedmodels.AuthCookies, error)
	// Logout revokes the session and returns expired cookies that overwrite the client's tokens.
	Logout(ctx context.Context, cookies sharedmodels.AuthCookies) (sharedmodels.AuthCookies, error)
	LogoutAll(ctx context.Context, userID int64) error
}

// Authenticator is what the middleware needs: check a request's tokens, or renew them.
type Authenticator interface {
	Authenticate(ctx context.Context, cookies sharedmodels.AuthCookies) (userID int64, err error)
	Refresh(ctx context.Context, cookies sharedmodels.AuthCookies) (sharedmodels.AuthCookies, error)
}

/*
Login:
Check password + username -> cookies

Logout:
expire refresh and session -> cookies

Register:
Validate, Save data -> cookies

General use:
Validate -> cookies
Validate -> cookies

*/
