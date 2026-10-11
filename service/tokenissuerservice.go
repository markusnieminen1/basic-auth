package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/markusnieminen1/basic-auth/components/caching"
	"github.com/markusnieminen1/basic-auth/components/token"
	"github.com/markusnieminen1/basic-auth/setup"
)

// TokenIssuerService combines the access and refresh strategies with the token lifetimes
// and the access token blacklist (kept in the optional cache).
type TokenIssuerService struct {
	access     token.AccessStrategy
	refresh    token.RefreshStrategy
	cache      caching.Store // optional, nil disables the blacklist
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewTokenIssuerService wires the token issuer. Access and refresh are required, cache may be nil.
func NewTokenIssuerService(access token.AccessStrategy, refresh token.RefreshStrategy, cache caching.Store) (*TokenIssuerService, error) {
	if access == nil {
		return nil, fmt.Errorf("%w: access token strategy", ErrMissingDependency)
	}
	if refresh == nil {
		return nil, fmt.Errorf("%w: refresh token strategy", ErrMissingDependency)
	}
	return &TokenIssuerService{
		access:     access,
		refresh:    refresh,
		cache:      cache,
		accessTTL:  time.Duration(setup.ACCESS_TOKEN_EXPIRY_MIN) * time.Minute,
		refreshTTL: time.Duration(setup.REFRESH_TOKEN_EXPIRY_DAYS) * time.Hour * 24,
	}, nil
}

func (t *TokenIssuerService) IssueAccessToken(ctx context.Context, userID int64) (string, time.Time, error) {
	return t.access.Issue(ctx, userID, t.accessTTL)
}

func (t *TokenIssuerService) ValidateAccessToken(ctx context.Context, rawToken string) (int64, error) {
	if t.cache != nil {
		if _, err := t.cache.Get(ctx, accessBlacklistKey(rawToken)); err == nil {
			return 0, errInvalidCredentials
		} else if !errors.Is(err, caching.ErrMiss) {
			return 0, err
		}
	}
	return t.access.Validate(ctx, rawToken)
}

// RevokeAccessToken blacklists the token until it would have expired anyway.
// Without a cache there is no blacklist, so access tokens simply expire on their own.
func (t *TokenIssuerService) RevokeAccessToken(ctx context.Context, rawToken string, validUntil time.Time) error {
	if t.cache == nil {
		return nil
	}
	ttl := time.Until(validUntil)
	if ttl <= 0 {
		return nil
	}
	return t.cache.Set(ctx, accessBlacklistKey(rawToken), []byte("revoked"), ttl)
}

func (t *TokenIssuerService) IssueRefreshToken(ctx context.Context) (string, time.Time, error) {
	return t.refresh.Issue(ctx, t.refreshTTL)
}

func (t *TokenIssuerService) HashRefreshToken(rawToken string) (string, error) {
	return t.refresh.Hash(rawToken)
}
