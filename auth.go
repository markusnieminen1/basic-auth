// Package auth is the composition root: it takes the chosen components (hasher, token
// strategies, repositories, cache) and wires them into the services and middleware.
package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/markusnieminen1/basic-auth/components/caching"
	"github.com/markusnieminen1/basic-auth/components/hashing"
	"github.com/markusnieminen1/basic-auth/components/token"
	"github.com/markusnieminen1/basic-auth/handlers"
	"github.com/markusnieminen1/basic-auth/service"
	"github.com/markusnieminen1/basic-auth/setup"
	"github.com/markusnieminen1/basic-auth/store/session"
	"github.com/markusnieminen1/basic-auth/store/user"
)

// Config selects the implementation behind every swappable component.
// Hasher, Access, Refresh, Users and Sessions are required. Cache is optional.
type Config struct {
	Hasher   hashing.PasswordHasher
	Access   token.AccessStrategy
	Refresh  token.RefreshStrategy
	Users    user.Repository
	Sessions session.Repository
	Cache    caching.Store // nil disables the session cache and the access token blacklist
}

// App holds the wired services. Handlers only receive the services they actually need.
type App struct {
	AccountService        service.AccountService
	AuthenticationService service.AuthenticationService
	Authenticator         service.Authenticator
	Middleware            AuthMiddleware
}

type AuthMiddleware struct {
	RatelimitMidWare      func(http.Handler) http.Handler // Ratelimiter for auth
	ExtractCookiesMidWare func(http.Handler) http.Handler // Extract tokens from request.
	ValidateTokenMidWare  func(http.Handler) http.Handler // Validate access token is valid. If only refresh is valid, renew access token.

	// RequireAuthMidware wraps ratelimiter -> ExtractCookiesMidWare -> ValidateTokenMidWare and answers 401
	// to anonymous requests. The wrapped handler always gets a user ID: handlers.UserID(r) is never nil.
	RequireAuthMidware func(http.Handler) http.Handler
	// OptionalAuthMidware is the same chain without the 401: handlers.UserID(r) is nil for anonymous requests.
	OptionalAuthMidware func(http.Handler) http.Handler
}

// New wires the app from the config. It fails if a required component is missing,
// so the services never have to check their dependencies at request time.
func New(cfg Config) (*App, error) {
	accounts, err := service.NewAccountManagerService(cfg.Users, cfg.Sessions, cfg.Hasher)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	tokens, err := service.NewTokenIssuerService(cfg.Access, cfg.Refresh, cfg.Cache)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	authentication, err := service.NewAuthenticationManagerService(cfg.Users, cfg.Sessions, tokens, cfg.Hasher, cfg.Cache)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	return &App{
		AccountService:        accounts,
		AuthenticationService: authentication,
		Authenticator:         authentication,
		Middleware:            newAuthMiddleware(authentication),
	}, nil
}

func newAuthMiddleware(authenticator service.Authenticator) AuthMiddleware {
	generalRateLimiter := handlers.NewSimpleRateLimiter(setup.RequestPerInterval, time.Duration(setup.RequesIntervalMillis)*time.Millisecond)
	protectedRateLimiter := handlers.NewSimpleRateLimiter(setup.ProtectedRouteRequestPerInterval, time.Duration(setup.ProtectedRouteRequesIntervalMillis)*time.Millisecond)
	validateToken := handlers.NewValidateTokenMiddleware(authenticator)

	optional := func(next http.Handler) http.Handler {
		return protectedRateLimiter.Handler(handlers.ExtractCookies(validateToken(next)))
	}
	required := func(next http.Handler) http.Handler {
		return optional(handlers.RequireAuth(next))
	}

	return AuthMiddleware{
		RatelimitMidWare:      generalRateLimiter.Handler,
		ExtractCookiesMidWare: handlers.ExtractCookies,
		ValidateTokenMidWare:  validateToken,
		RequireAuthMidware:    required,
		OptionalAuthMidware:   optional,
	}
}

/*
TODO: IMPLEMENT IN THE FUTURE

	type AuthHandlers struct {
		LoginHandler        http.Handler // TO BE IMPLEMENTED LATER
		LogoutHandler       http.Handler // TO BE IMPLEMENTED LATER
		RegisterUserHandler http.Handler // TO BE IMPLEMENTED LATER
	}
*/
