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

// ErrInvalidCredentials is returned for every failed login or token check, whatever the cause
// (unknown user, wrong password, unknown, expired or revoked token), so a caller cannot tell them apart.
// Any other error is an internal failure, for example the database being down.
var ErrInvalidCredentials = errors.New("invalid credentials")

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
		return 0, ErrInvalidCredentials
	}
	return a.tokens.ValidateAccessToken(ctx, cookies.AccessToken.Value)
}

func (a *AuthenticationManagerService) Login(ctx context.Context, input sharedmodels.LoginInput) (sharedmodels.AuthCookies, error) {
	found, err := a.users.GetByUsername(ctx, input.Username)
	if errors.Is(err, user.ErrNotFound) {
		_, _ = a.hasher.Verify(input.Password, a.unknownUserHash)
		return sharedmodels.AuthCookies{}, ErrInvalidCredentials
	}
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	valid, err := a.hasher.Verify(input.Password, found.PasswordHash)
	if err != nil || !valid {
		return sharedmodels.AuthCookies{}, ErrInvalidCredentials
	}
	return a.issueSession(ctx, found.UserID)
}

func (a *AuthenticationManagerService) Refresh(ctx context.Context, cookies sharedmodels.AuthCookies) (sharedmodels.AuthCookies, error) {
	if cookies.RefreshToken == nil {
		return sharedmodels.AuthCookies{}, ErrInvalidCredentials
	}
	tokenHash, err := a.tokens.HashRefreshToken(cookies.RefreshToken.Value)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	stored, err := a.getSession(ctx, tokenHash)
	if errors.Is(err, session.ErrNotFound) {
		return sharedmodels.AuthCookies{}, ErrInvalidCredentials
	}
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	// Deleting the session is what accepts the token. Of several requests with the same
	// refresh token only one deletes it, and the others are told the token is no good.
	revoked, err := a.sessions.Revoke(ctx, tokenHash)
	if err != nil {
		return sharedmodels.AuthCookies{}, err
	}
	a.deleteCachedSession(ctx, tokenHash)
	if !revoked {
		return sharedmodels.AuthCookies{}, ErrInvalidCredentials
	}
	return a.issueSession(ctx, stored.UserID)
}

// Logout revokes the session behind the refresh token and the access token, then returns
// cookies with the same names and an empty value that expire at once. Setting them
// overwrites and removes the client's tokens. Nothing is returned on error, so the client
// keeps its tokens and can try again.
func (a *AuthenticationManagerService) Logout(ctx context.Context, cookies sharedmodels.AuthCookies) (sharedmodels.AuthCookies, error) {
	if cookies.AccessToken != nil {
		if err := a.tokens.RevokeAccessToken(ctx, cookies.AccessToken.Value, cookies.AccessToken.Expires); err != nil {
			return sharedmodels.AuthCookies{}, err
		}
	}
	if cookies.RefreshToken != nil {
		tokenHash, err := a.tokens.HashRefreshToken(cookies.RefreshToken.Value)
		if err != nil {
			return sharedmodels.AuthCookies{}, err
		}
		if _, err = a.sessions.Revoke(ctx, tokenHash); err != nil {
			return sharedmodels.AuthCookies{}, err
		}
		a.deleteCachedSession(ctx, tokenHash)
	}
	return expiredCookies(), nil
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
		AccessToken:  &http.Cookie{Name: setup.ACCESS_TOKEN_NAME, Value: accessToken, Path: cookiePath, Expires: accessExpiresAt, HttpOnly: true, SameSite: http.SameSiteStrictMode},
		RefreshToken: &http.Cookie{Name: setup.REFRESH_TOKEN_NAME, Value: refreshToken, Path: cookiePath, Expires: refreshExpiresAt, HttpOnly: true, SameSite: http.SameSiteStrictMode},
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

// cookiePath is fixed so that a cookie set by one endpoint is overwritten by another,
// for example the login cookies by the logout cookies. A default path depends on the URL.
const cookiePath = "/"

// expiredCookies returns cookies that replace the token cookies and tell the browser to drop them.
func expiredCookies() sharedmodels.AuthCookies {
	expire := func(name string) *http.Cookie {
		return &http.Cookie{Name: name, Value: "", Path: cookiePath, Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	}
	return sharedmodels.AuthCookies{AccessToken: expire(setup.ACCESS_TOKEN_NAME), RefreshToken: expire(setup.REFRESH_TOKEN_NAME)}
}

func refreshSessionKey(tokenHash string) string {
	return "auth:refresh-session:" + tokenHash
}

func accessBlacklistKey(token string) string {
	return "auth:access-blacklist:" + token
}

var _ AuthenticationService = (*AuthenticationManagerService)(nil)
var _ Authenticator = (*AuthenticationManagerService)(nil)
