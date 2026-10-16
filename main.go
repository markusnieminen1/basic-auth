// Package basic-auth has basic functionality for Authentication and later Authorization.
//
// Quick start:
//
//	import (
//		auth "github.com/markusnieminen1/basic-auth"
//		)
//	app, err := auth.NewAuthApp(auth.Config{})
//	defer app.Close()
//	auth_middleware := auth.newAuthMiddleware(app.Authenticator)
package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/markusnieminen1/basic-auth/components/caching"
	"github.com/markusnieminen1/basic-auth/components/hashing"
	"github.com/markusnieminen1/basic-auth/components/hashing/bcrypt"
	"github.com/markusnieminen1/basic-auth/components/token"
	"github.com/markusnieminen1/basic-auth/components/token/jwt"
	"github.com/markusnieminen1/basic-auth/components/token/uuid"
	"github.com/markusnieminen1/basic-auth/handlers"
	"github.com/markusnieminen1/basic-auth/service"
	"github.com/markusnieminen1/basic-auth/setup"
	"github.com/markusnieminen1/basic-auth/store/database/sqlite"
	"github.com/markusnieminen1/basic-auth/store/database/sqlite/sqlitemattn"
	"github.com/markusnieminen1/basic-auth/store/session"
	sessionsqlite "github.com/markusnieminen1/basic-auth/store/session/sqlite"
	"github.com/markusnieminen1/basic-auth/store/user"
	usersqlite "github.com/markusnieminen1/basic-auth/store/user/sqlite"
)

// Config allows making setup differing from default setup
//
//	Hasher   bcrypt
//	Access   Ed25519 signed JWT, key loaded from (or created in) jwt.DefaultKeyFile
//	Refresh  random UUID, stored as its SHA-256 hash
//	Users    sqlite
//	Sessions sqlite
//
// Cache has no default
type Config struct {
	Hasher   hashing.PasswordHasher
	Access   token.AccessTokenLogic
	Refresh  token.RefreshTokenLogic
	Users    user.Repository
	Sessions session.Repository
	Cache    caching.Store // nil disables the session cache and the access token blacklist

	DB *sql.DB // used by the default Users and Sessions. The caller keeps ownership and closes it.
}

type App struct {
	AccountService        service.AccountService
	AuthenticationService service.AuthenticationService
	Authenticator         service.Authenticator
	Middleware            Middleware

	cfg     Config  // used for ConfigTest
	ownedDB *sql.DB // set only when New opened the default database
}

// Close releases what New opened itself. Components passed in through Config (including Config.DB)
// stay open and are the caller's to close.
func (a *App) Close() error {

	if a.ownedDB == nil {
		return nil
	}

	return a.ownedDB.Close()
}

type Middleware struct {
	Ratelimiter    func(http.Handler) http.Handler
	ExtractCookies func(http.Handler) http.Handler
	ValidateToken  func(http.Handler) http.Handler

	RequireAuthRoute  func(http.Handler) http.Handler // User id will be present in the handler
	OptionalAuthRoute func(http.Handler) http.Handler // User id might not be present in the handler
}

func NewAuthApp(cfg Config) (app *App, err error) {

	var ownedDB *sql.DB

	// Only used for auth specific DB.
	defer func() {
		if err != nil && ownedDB != nil {
			ownedDB.Close()
		}
	}()

	if cfg.Hasher == nil {
		if cfg.Hasher, err = bcrypt.New(); err != nil {
			return nil, fmt.Errorf("auth: default hasher: %w", err)
		}
	}

	if cfg.Access == nil {
		if cfg.Access, err = jwt.NewEdDSAFromFile(jwt.DefaultKeyFile); err != nil {
			return nil, fmt.Errorf("auth: default access token strategy: %w", err)
		}
	}

	if cfg.Refresh == nil {
		cfg.Refresh = uuid.NewRefresh()
	}

	if cfg.Users == nil || cfg.Sessions == nil {

		db := cfg.DB

		if db == nil {

			if db, err = sqlitemattn.Open(context.Background(), setup.AuthDbDefaultPath); err != nil {
				return nil, fmt.Errorf("auth: default database: %w", err)
			}
			ownedDB = db

		} else if err = sqlite.Migrate(context.Background(), db); err != nil {
			return nil, fmt.Errorf("auth: migrate database: %w", err)
		}

		if cfg.Users == nil {
			cfg.Users = usersqlite.New(db)
		}

		if cfg.Sessions == nil {
			cfg.Sessions = sessionsqlite.New(db)
		}
	}

	app, err = buildApp(cfg)

	if err != nil {
		return nil, err
	}

	app.ownedDB = ownedDB

	return app, nil
}

// buildApp builds the services and middleware from a config.
func buildApp(cfg Config) (*App, error) {

	accounts, err := service.NewAccountManagerService(cfg.Users, cfg.Sessions, cfg.Hasher)

	if err != nil {
		return nil, fmt.Errorf("buildApp: %w", err)
	}
	tokens, err := service.NewTokenIssuerService(cfg.Access, cfg.Refresh, cfg.Cache)

	if err != nil {
		return nil, fmt.Errorf("buildApp: %w", err)
	}
	authentication, err := service.NewAuthenticationManagerService(cfg.Users, cfg.Sessions, tokens, cfg.Hasher, cfg.Cache)

	if err != nil {
		return nil, fmt.Errorf("buildApp: %w", err)
	}

	return &App{
		AccountService:        accounts,
		AuthenticationService: authentication,
		Authenticator:         authentication,
		Middleware:            newAuthMiddleware(authentication),
		cfg:                   cfg,
	}, nil
}

func newAuthMiddleware(authenticator service.Authenticator) Middleware {
	generalRateLimiter := handlers.NewSimpleRateLimiter(setup.RequestPerInterval, time.Duration(setup.RequesIntervalMillis)*time.Millisecond)
	protectedRateLimiter := handlers.NewSimpleRateLimiter(setup.ProtectedRouteRequestPerInterval, time.Duration(setup.ProtectedRouteRequesIntervalMillis)*time.Millisecond)
	validateToken := handlers.NewValidateTokenMiddleware(authenticator)

	optional := func(next http.Handler) http.Handler {
		return protectedRateLimiter.Handler(handlers.ExtractCookies(validateToken(next)))
	}
	required := func(next http.Handler) http.Handler {
		return optional(handlers.RequireAuth(next))
	}

	return Middleware{
		Ratelimiter:       generalRateLimiter.Handler,
		ExtractCookies:    handlers.ExtractCookies,
		ValidateToken:     validateToken,
		RequireAuthRoute:  required,
		OptionalAuthRoute: optional,
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
