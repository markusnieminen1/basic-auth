package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/markusnieminen1/basic-auth/components/caching"
	"github.com/markusnieminen1/basic-auth/components/hashing"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/setup"
	"github.com/markusnieminen1/basic-auth/store/session"
	"github.com/markusnieminen1/basic-auth/store/user"
)

var errInvalidCredentials = errors.New("invalid credentials")

type AuthenticationManagerService struct {
	users    user.Repository
	sessions session.Repository
	tokens   *TokenIssuerService
	hasher   hashing.PasswordHasher
	cache    caching.Store // optional, nil disables session caching

	// unknownUserHash is verified against when the username does not exist, so that
	// login takes about as long for unknown users as for known ones.
	unknownUserHash string
}

// NewAuthenticationManagerService wires the authentication service. Everything except cache is required.
func NewAuthenticationManagerService(users user.Repository, sessions session.Repository, tokens *TokenIssuerService, hasher hashing.PasswordHasher, cache caching.Store) (*AuthenticationManagerService, error) {
	if users == nil {
		return nil, fmt.Errorf("%w: user repository", ErrMissingDependency)
	}
	if sessions == nil {
		return nil, fmt.Errorf("%w: session repository", ErrMissingDependency)
	}
	if tokens == nil {
		return nil, fmt.Errorf("%w: token issuer", ErrMissingDependency)
	}
	if hasher == nil {
		return nil, fmt.Errorf("%w: password hasher", ErrMissingDependency)
	}
	unknownUserHash, err := hasher.Hash("timing-equaliser-not-a-real-password")
	if err != nil {
		return nil, fmt.Errorf("auth: preparing the password hasher: %w", err)
	}
	return &AuthenticationManagerService{users: users, sessions: sessions, tokens: tokens, hasher: hasher, cache: cache, unknownUserHash: unknownUserHash}, nil
}

func (a *AuthenticationManagerService) Authenticate(ctx context.Context, cookies sharedmodels.AuthCookies) (int64, error) {
	if cookies.AccessToken == nil {
		return 0, errInvalidCredentials
	}
	return a.tokens.ValidateAccessToken(ctx, cookies.AccessToken.Value)
}

func (a *AuthenticationManagerService) Login(ctx context.Context, input sharedmodels.LoginInput) (sharedmodels.AuthCookies, error) {
	found, err := a.users.GetByUsername(ctx, input.Username)
	if errors.Is(err, user.ErrNotFound) {
		_, _ = a.hasher.Verify(input.Password, a.unknownUserHash)
		return sharedmodels.AuthCookies{}, errInvalidCredentials
	}
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	valid, err := a.hasher.Verify(input.Password, found.PasswordHash)
	if err != nil || !valid {
		return sharedmodels.AuthCookies{}, errInvalidCredentials
	}
	return a.issueSession(ctx, found.UserID)
}

func (a *AuthenticationManagerService) Refresh(ctx context.Context, cookies sharedmodels.AuthCookies) (sharedmodels.AuthCookies, error) {
	if cookies.RefreshToken == nil {
		return sharedmodels.AuthCookies{}, errInvalidCredentials
	}
	tokenHash, err := a.tokens.HashRefreshToken(cookies.RefreshToken.Value)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	stored, err := a.getSession(ctx, tokenHash)
	if errors.Is(err, session.ErrNotFound) {
		return sharedmodels.AuthCookies{}, errInvalidCredentials
	}
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	if err = a.sessions.Revoke(ctx, tokenHash); err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	a.deleteCachedSession(ctx, tokenHash)
	return a.issueSession(ctx, stored.UserID)
}

func (a *AuthenticationManagerService) Logout(ctx context.Context, cookies sharedmodels.AuthCookies) error {
	if cookies.RefreshToken == nil && cookies.AccessToken == nil {
		return nil
	}
	if cookies.AccessToken != nil {
		if err := a.tokens.RevokeAccessToken(ctx, cookies.AccessToken.Value, cookies.AccessToken.Expires); err != nil {
			return err
		}
	}
	if cookies.RefreshToken == nil {
		return nil
	}
	tokenHash, err := a.tokens.HashRefreshToken(cookies.RefreshToken.Value)
	if err != nil {
		return err
	}
	if err = a.sessions.Revoke(ctx, tokenHash); err != nil {
		return err
	}
	a.deleteCachedSession(ctx, tokenHash)
	return nil
}

func (a *AuthenticationManagerService) LogoutAll(ctx context.Context, userID int64) error {
	return a.sessions.RevokeAllForUser(ctx, userID)
}

func (a *AuthenticationManagerService) issueSession(ctx context.Context, userID int64) (sharedmodels.AuthCookies, error) {
	accessToken, accessExpiresAt, err := a.tokens.IssueAccessToken(ctx, userID)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	refreshToken, refreshExpiresAt, err := a.tokens.IssueRefreshToken(ctx)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	refreshHash, err := a.tokens.HashRefreshToken(refreshToken)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	if err = a.sessions.Create(ctx, session.Session{UserID: userID, RefreshTokenHash: refreshHash, ValidUntil: refreshExpiresAt}); err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	return sharedmodels.AuthCookies{
		AccessToken:  &http.Cookie{Name: setup.ACCESS_TOKEN_NAME, Value: accessToken, Expires: accessExpiresAt, HttpOnly: true},
		RefreshToken: &http.Cookie{Name: setup.REFRESH_TOKEN_NAME, Value: refreshToken, Expires: refreshExpiresAt, HttpOnly: true},
		UserID:       &userID,
	}, nil
}

func (a *AuthenticationManagerService) getSession(ctx context.Context, tokenHash string) (session.Session, error) {
	if a.cache != nil {
		data, err := a.cache.Get(ctx, refreshSessionKey(tokenHash))
		if err == nil {
			var cached session.Session
			if err = json.Unmarshal(data, &cached); err != nil {
				return session.Session{}, err
			}
			return cached, nil
		}
		if !errors.Is(err, caching.ErrMiss) {
			return session.Session{}, err
		}
	}

	storedSession, err := a.sessions.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return session.Session{}, err
	}
	if a.cache != nil {
		if data, marshalErr := json.Marshal(storedSession); marshalErr == nil {
			_ = a.cache.Set(ctx, refreshSessionKey(tokenHash), data, time.Until(storedSession.ValidUntil))
		}
	}
	return storedSession, nil
}

func (a *AuthenticationManagerService) deleteCachedSession(ctx context.Context, tokenHash string) {
	if a.cache != nil {
		_ = a.cache.Delete(ctx, refreshSessionKey(tokenHash))
	}
}

func refreshSessionKey(tokenHash string) string {
	return "auth:refresh-session:" + tokenHash
}

func accessBlacklistKey(token string) string {
	return "auth:access-blacklist:" + token
}

var _ AuthenticationService = (*AuthenticationManagerService)(nil)
var _ Authenticator = (*AuthenticationManagerService)(nil)
