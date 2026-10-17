package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/handlers"
	"github.com/markusnieminen1/basic-auth/store/database/sqlite/sqlitemattn"
	sessionsqlite "github.com/markusnieminen1/basic-auth/store/session/sqlite"
	usersqlite "github.com/markusnieminen1/basic-auth/store/user/sqlite"
)

const (
	configTestUsername = "configtest"
	configTestEmail    = "configtest@example.com"
	configTestPassword = "Config-test-1!"
	configTestNewPass  = "Config-test-2!"
)

// ConfigTest checks that registration, login, token refresh, logout, password change and
// account deletion work with the components this app was configured with, and that the
// middleware accepts and rejects requests as it should. Call it at startup to fail fast
// on a broken config, for example an unreadable key file or an unusable cache.
//
// The test never touches the app's own database. It runs on a private sqlite database in a
// temporary directory that is removed afterwards, and replaces Users and Sessions with
// sqlite repositories on it, whatever the app uses. The hasher, the token strategies and the
// cache are the app's own, so the cache can hold a few short lived test entries afterwards.
// Make sure the app's config is the one that will serve, and do not run it concurrently with
// anything that depends on an empty cache.
//
// It stops at the first failed check, and the error names it.
func (a *App) ConfigTest(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "basic-auth-configtest-")
	if err != nil {
		return fmt.Errorf("auth: config test: temporary directory: %w", err)
	}
	defer os.RemoveAll(dir)

	db, err := sqlitemattn.Open(ctx, filepath.Join(dir, "configtest.db"))
	if err != nil {
		return fmt.Errorf("auth: config test: private database: %w", err)
	}
	defer db.Close()

	cfg := a.cfg
	cfg.Users = usersqlite.New(db)
	cfg.Sessions = sessionsqlite.New(db)
	sandbox, err := buildApp(cfg)
	if err != nil {
		return fmt.Errorf("auth: config test: %w", err)
	}

	if err = runChecks(ctx, sandbox, cfg.Cache != nil); err != nil {
		return fmt.Errorf("auth: config test: %w", err)
	}
	return nil
}

// runChecks drives the sandbox through a user's life. hasCache tells whether logout can
// revoke access tokens, which needs the cache for the blacklist.
func runChecks(ctx context.Context, app *App, hasCache bool) error {
	var (
		userID  int64
		cookies sharedmodels.AuthCookies
	)
	login := func(password string) (sharedmodels.AuthCookies, error) {
		return app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: configTestUsername, Password: password})
	}
	// authenticated reports whether the access token of the cookies still gets through.
	authenticated := func(c sharedmodels.AuthCookies) bool {
		id, err := app.Authenticator.Authenticate(ctx, c)
		return err == nil && id == userID
	}
	// refreshable reports whether the refresh token can still be exchanged for new tokens.
	refreshable := func(c sharedmodels.AuthCookies) bool {
		_, err := app.AuthenticationService.Refresh(ctx, c)
		return err == nil
	}

	checks := []struct {
		name string
		run  func() error
	}{
		{"register", func() error {
			user, err := app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: configTestEmail, Username: configTestUsername, Password: configTestPassword})
			if err != nil {
				return err
			}
			userID = user.UserID
			return nil
		}},
		{"register rejects a taken username", func() error {
			_, err := app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: "other-" + configTestEmail, Username: configTestUsername, Password: configTestPassword})
			return mustFail(err, "second registration with the same username succeeded")
		}},
		{"login rejects a wrong password", func() error {
			_, err := login("not-the-" + configTestPassword)
			return mustFail(err, "login succeeded with a wrong password")
		}},
		{"login", func() error {
			var err error
			cookies, err = login(configTestPassword)
			if err != nil {
				return err
			}
			if cookies.AccessToken == nil || cookies.RefreshToken == nil {
				return errors.New("login did not return both tokens")
			}
			return nil
		}},
		{"access token authenticates", func() error {
			if !authenticated(cookies) {
				return errors.New("the access token from login was not accepted")
			}
			return nil
		}},
		{"middleware", func() error { return checkMiddleware(app, cookies, userID) }},
		{"refresh rotates the refresh token", func() error {
			renewed, err := app.AuthenticationService.Refresh(ctx, cookies)
			if err != nil {
				return err
			}
			if renewed.RefreshToken.Value == cookies.RefreshToken.Value {
				return errors.New("refresh token was not rotated")
			}
			if refreshable(cookies) {
				return errors.New("the old refresh token still works after rotation")
			}
			cookies = renewed
			return nil
		}},
		{"logout revokes the session", func() error {
			// A cookie read from a request has no expiry, like the ones a browser sends back.
			sent := sharedmodels.AuthCookies{
				AccessToken:  &http.Cookie{Name: cookies.AccessToken.Name, Value: cookies.AccessToken.Value},
				RefreshToken: &http.Cookie{Name: cookies.RefreshToken.Name, Value: cookies.RefreshToken.Value},
			}
			expired, err := app.AuthenticationService.Logout(ctx, sent)
			if err != nil {
				return err
			}
			for _, c := range []*http.Cookie{expired.AccessToken, expired.RefreshToken} {
				if c == nil || c.Value != "" || c.MaxAge >= 0 {
					return errors.New("logout did not return expired cookies to overwrite the tokens")
				}
			}
			if expired.AccessToken.Name != cookies.AccessToken.Name || expired.RefreshToken.Name != cookies.RefreshToken.Name {
				return errors.New("the expired cookies do not have the names of the token cookies")
			}
			if refreshable(cookies) {
				return errors.New("refresh token still works after logout")
			}
			if hasCache && authenticated(cookies) {
				return errors.New("access token still accepted after logout, the cache blacklist did not catch it")
			}
			return nil
		}},
		{"logout all ends every device", func() error {
			phone, err := login(configTestPassword)
			if err != nil {
				return err
			}
			laptop, err := login(configTestPassword)
			if err != nil {
				return err
			}
			if err = app.AuthenticationService.LogoutAll(ctx, userID); err != nil {
				return err
			}
			if refreshable(phone) || refreshable(laptop) {
				return errors.New("a session survived logout of all devices")
			}
			return nil
		}},
		{"password change", func() error {
			session, err := login(configTestPassword)
			if err != nil {
				return err
			}
			err = app.AccountService.ChangePassword(ctx, sharedmodels.ChangePasswordInput{UserID: userID, Current: "not-the-" + configTestPassword, Replacement: configTestNewPass})
			if err = mustFail(err, "password changed with a wrong current password"); err != nil {
				return err
			}
			err = app.AccountService.ChangePassword(ctx, sharedmodels.ChangePasswordInput{UserID: userID, Current: configTestPassword, Replacement: configTestNewPass})
			if err != nil {
				return err
			}
			if refreshable(session) {
				return errors.New("a session survived the password change")
			}
			if _, err = login(configTestPassword); err == nil {
				return errors.New("the old password still works")
			}
			if _, err = login(configTestNewPass); err != nil {
				return fmt.Errorf("the new password does not work: %w", err)
			}
			return nil
		}},
		{"account deletion", func() error {
			session, err := login(configTestNewPass)
			if err != nil {
				return err
			}
			if err = app.AccountService.Delete(ctx, userID); err != nil {
				return err
			}
			if refreshable(session) {
				return errors.New("a session survived account deletion")
			}
			_, err = login(configTestNewPass)
			return mustFail(err, "a deleted user can still log in")
		}},
	}

	for _, check := range checks {
		if err := check.run(); err != nil {
			return fmt.Errorf("%s: %w", check.name, err)
		}
	}
	return nil
}

// checkMiddleware sends requests through RequireAuth and OptionalAuth: anonymous requests
// must be refused or see no user, and requests with the session cookies must see userID.
func checkMiddleware(app *App, cookies sharedmodels.AuthCookies, userID int64) error {
	var seen *int64
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = handlers.UserID(r)
		w.WriteHeader(http.StatusOK)
	})
	do := func(mw func(http.Handler) http.Handler, withCookies bool) int {
		seen = nil
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if withCookies {
			req.AddCookie(cookies.AccessToken)
			req.AddCookie(cookies.RefreshToken)
		}
		rec := httptest.NewRecorder()
		mw(next).ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(app.Middleware.RequireAuthRoute, false); code != http.StatusUnauthorized {
		return fmt.Errorf("RequireAuth answered %d to an anonymous request, want %d", code, http.StatusUnauthorized)
	}
	if code := do(app.Middleware.RequireAuthRoute, true); code != http.StatusOK || seen == nil || *seen != userID {
		return fmt.Errorf("RequireAuth did not let the logged in user through (status %d, user %v)", code, seen)
	}
	if code := do(app.Middleware.OptionalAuthRoute, false); code != http.StatusOK || seen != nil {
		return fmt.Errorf("OptionalAuth should pass an anonymous request without a user (status %d, user %v)", code, seen)
	}
	if code := do(app.Middleware.OptionalAuthRoute, true); code != http.StatusOK || seen == nil || *seen != userID {
		return fmt.Errorf("OptionalAuth did not see the logged in user (status %d, user %v)", code, seen)
	}
	return nil
}

// mustFail turns an operation that was supposed to be refused into an error when it was not.
func mustFail(err error, message string) error {
	if err == nil {
		return errors.New(message)
	}
	return nil
}
