package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/markusnieminen1/basic-auth/components/caching"
	cachedummy "github.com/markusnieminen1/basic-auth/components/caching/dummy"
	hashdummy "github.com/markusnieminen1/basic-auth/components/hashing/dummy"
	tokendummy "github.com/markusnieminen1/basic-auth/components/token/dummy"
	"github.com/markusnieminen1/basic-auth/components/token/jwt"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/handlers"
	"github.com/markusnieminen1/basic-auth/service"
	"github.com/markusnieminen1/basic-auth/setup"
	sessionmemory "github.com/markusnieminen1/basic-auth/store/session/memory"
	userdummy "github.com/markusnieminen1/basic-auth/store/user/dummy"
)

var ctx = context.Background()

const password = "Sup3r-secret!"

func dummyConfig(cache caching.Store) Config {
	return Config{
		Hasher:   hashdummy.New(),
		Access:   tokendummy.NewAccess(),
		Refresh:  tokendummy.NewRefresh(),
		Users:    userdummy.New(),
		Sessions: sessionmemory.New(),
		Cache:    cache,
	}
}

// newApp wires every component from its dummy and registers the user "alice".
func newApp(t *testing.T, cache caching.Store) (*App, int64) {
	t.Helper()
	app, err := New(dummyConfig(cache))
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: "alice@example.com", Username: "alice", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	return app, user.UserID
}

func login(t *testing.T, app *App) sharedmodels.AuthCookies {
	t.Helper()
	cookies, err := app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "alice", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	return cookies
}

func TestNewRequiresComponents(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, service.ErrMissingDependency) {
		t.Fatalf("expected ErrMissingDependency for empty config, got %v", err)
	}

	// Every required component on its own must be reported when missing.
	missing := map[string]func(*Config){
		"hasher":   func(c *Config) { c.Hasher = nil },
		"access":   func(c *Config) { c.Access = nil },
		"refresh":  func(c *Config) { c.Refresh = nil },
		"users":    func(c *Config) { c.Users = nil },
		"sessions": func(c *Config) { c.Sessions = nil },
	}
	for name, drop := range missing {
		cfg := dummyConfig(nil)
		drop(&cfg)
		if _, err := New(cfg); !errors.Is(err, service.ErrMissingDependency) {
			t.Errorf("without %s: got %v, want ErrMissingDependency", name, err)
		}
	}
	if _, err := New(dummyConfig(nil)); err != nil {
		t.Errorf("the cache is optional, got %v", err)
	}
}

func TestLoginRefreshLogoutCycle(t *testing.T) {
	app, userID := newApp(t, cachedummy.New())
	cookies := login(t, app)

	if got, err := app.Authenticator.Authenticate(ctx, cookies); err != nil || got != userID {
		t.Fatalf("Authenticate = %d, %v; want %d", got, err, userID)
	}

	// Refresh rotates the refresh token: the old one stops working.
	renewed, err := app.AuthenticationService.Refresh(ctx, cookies)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.RefreshToken.Value == cookies.RefreshToken.Value {
		t.Error("refresh token was not rotated")
	}
	if _, err = app.AuthenticationService.Refresh(ctx, cookies); err == nil {
		t.Error("the old refresh token still works after rotation")
	}

	// Logout revokes both tokens.
	if err = app.AuthenticationService.Logout(ctx, renewed); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Authenticator.Authenticate(ctx, renewed); err == nil {
		t.Error("access token still valid after logout")
	}
	if _, err = app.AuthenticationService.Refresh(ctx, renewed); err == nil {
		t.Error("refresh token still valid after logout")
	}
}

func TestCycleWithJWT(t *testing.T) {
	strategy, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := dummyConfig(cachedummy.New())
	cfg.Access = strategy
	app, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: "alice@example.com", Username: "alice", Password: password})
	if err != nil {
		t.Fatal(err)
	}

	cookies := login(t, app)
	if got, err := app.Authenticator.Authenticate(ctx, cookies); err != nil || got != user.UserID {
		t.Fatalf("Authenticate = %d, %v; want %d", got, err, user.UserID)
	}
	if err = app.AuthenticationService.Logout(ctx, cookies); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Authenticator.Authenticate(ctx, cookies); err == nil {
		t.Error("JWT still accepted after logout; the blacklist did not catch it")
	}
}

func TestLogoutAllEndsEveryDevice(t *testing.T) {
	app, userID := newApp(t, cachedummy.New())
	phone, laptop := login(t, app), login(t, app)

	if err := app.AuthenticationService.LogoutAll(ctx, userID); err != nil {
		t.Fatal(err)
	}
	for name, device := range map[string]sharedmodels.AuthCookies{"phone": phone, "laptop": laptop} {
		if _, err := app.AuthenticationService.Refresh(ctx, device); err == nil {
			t.Errorf("%s session survived LogoutAll", name)
		}
	}
}

func TestBadCredentialsLookTheSame(t *testing.T) {
	app, _ := newApp(t, nil)

	_, wrongPassword := app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "alice", Password: "nope"})
	_, unknownUser := app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "mallory", Password: password})
	if wrongPassword == nil || unknownUser == nil {
		t.Fatal("login succeeded with bad credentials")
	}
	if wrongPassword.Error() != unknownUser.Error() {
		t.Errorf("errors differ and reveal which usernames exist: %q vs %q", wrongPassword, unknownUser)
	}
}

// Without a cache there is no blacklist: logout still ends the session, but an access
// token simply lives until it expires.
func TestWorksWithoutCache(t *testing.T) {
	app, _ := newApp(t, nil)
	cookies := login(t, app)

	if err := app.AuthenticationService.Logout(ctx, cookies); err != nil {
		t.Fatal(err)
	}
	if _, err := app.AuthenticationService.Refresh(ctx, cookies); err == nil {
		t.Error("refresh token still valid after logout")
	}
}

func TestChangingThePasswordEndsEverySession(t *testing.T) {
	app, userID := newApp(t, cachedummy.New())
	phone, laptop := login(t, app), login(t, app)

	// A failed attempt must not sign anyone out.
	err := app.AccountService.ChangePassword(ctx, sharedmodels.ChangePasswordInput{UserID: userID, Current: "wrong", Replacement: "N3w-secret-pass!"})
	if err == nil {
		t.Fatal("password changed with the wrong current password")
	}
	if _, err = app.AuthenticationService.Refresh(ctx, phone); err != nil {
		t.Fatalf("a failed password change ended a session: %v", err)
	}

	err = app.AccountService.ChangePassword(ctx, sharedmodels.ChangePasswordInput{UserID: userID, Current: password, Replacement: "N3w-secret-pass!"})
	if err != nil {
		t.Fatal(err)
	}
	for name, device := range map[string]sharedmodels.AuthCookies{"phone": phone, "laptop": laptop} {
		if _, err = app.AuthenticationService.Refresh(ctx, device); err == nil {
			t.Errorf("%s session survived the password change", name)
		}
	}
	if _, err = app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "alice", Password: "N3w-secret-pass!"}); err != nil {
		t.Errorf("cannot log in with the new password: %v", err)
	}
}

func TestDeletingTheAccountEndsEverySession(t *testing.T) {
	app, userID := newApp(t, cachedummy.New())
	cookies := login(t, app)

	if err := app.AccountService.Delete(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.AuthenticationService.Refresh(ctx, cookies); err == nil {
		t.Error("session survived account deletion")
	}
	if _, err := app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "alice", Password: password}); err == nil {
		t.Error("deleted user can still log in")
	}
}

func TestAccountChangeNeedsPassword(t *testing.T) {
	app, userID := newApp(t, nil)

	_, err := app.AccountService.UpdateEmail(ctx, sharedmodels.UpdateEmailInput{UserID: userID, Email: "new@example.com", Password: "wrong"})
	if err == nil {
		t.Fatal("email changed with the wrong password")
	}
	updated, err := app.AccountService.UpdateEmail(ctx, sharedmodels.UpdateEmailInput{UserID: userID, Email: "new@example.com", Password: password})
	if err != nil || updated.Email != "new@example.com" {
		t.Fatalf("UpdateEmail = %+v, %v", updated, err)
	}
}

// serve runs a request through the given middleware and reports what the final handler
// saw, the response status and which cookies the middleware set.
func serve(t *testing.T, mw func(http.Handler) http.Handler, cookies ...*http.Cookie) (userID *int64, status int, set []*http.Cookie) {
	t.Helper()
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID = handlers.UserID(r)
	})
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	mw(final).ServeHTTP(rec, req)
	return userID, rec.Code, rec.Result().Cookies()
}

func TestRequireAuthMiddleware(t *testing.T) {
	app, userID := newApp(t, cachedummy.New())
	cookies := login(t, app)

	t.Run("valid access token", func(t *testing.T) {
		got, status, set := serve(t, app.Middleware.RequireAuthMidware, cookies.AccessToken, cookies.RefreshToken)
		if status != http.StatusOK || got == nil || *got != userID {
			t.Errorf("status %d, handler saw user %v, want %d", status, got, userID)
		}
		if len(set) != 0 {
			t.Errorf("middleware set cookies for a valid token: %v", set)
		}
	})

	t.Run("no cookies is rejected", func(t *testing.T) {
		called := false
		final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
		rec := httptest.NewRecorder()
		app.Middleware.RequireAuthMidware(final).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/protected", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", rec.Code)
		}
		if called {
			t.Error("the handler ran for an anonymous request")
		}
	})

	t.Run("expired access token is renewed from the refresh token", func(t *testing.T) {
		app, userID := newApp(t, cachedummy.New())
		cookies := login(t, app)
		expired, _, err := tokendummy.NewAccess().Issue(ctx, userID, -time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		stale := &http.Cookie{Name: setup.ACCESS_TOKEN_NAME, Value: expired}

		got, _, set := serve(t, app.Middleware.RequireAuthMidware, stale, cookies.RefreshToken)
		if got == nil || *got != userID {
			t.Fatalf("handler saw user %v, want %d", got, userID)
		}
		if len(set) != 2 {
			t.Errorf("expected new access and refresh cookies, got %v", set)
		}

		// The refresh token was rotated, so replaying the old one must not authenticate.
		if _, status, _ := serve(t, app.Middleware.RequireAuthMidware, stale, cookies.RefreshToken); status != http.StatusUnauthorized {
			t.Errorf("a replayed refresh token got status %d, want 401", status)
		}
	})

	// A browser deletes the access cookie once it expires, so only the refresh token arrives.
	t.Run("missing access token is renewed from the refresh token", func(t *testing.T) {
		app, userID := newApp(t, cachedummy.New())
		cookies := login(t, app)

		got, _, set := serve(t, app.Middleware.RequireAuthMidware, cookies.RefreshToken)
		if got == nil || *got != userID {
			t.Fatalf("handler saw user %v, want %d", got, userID)
		}
		if len(set) != 2 {
			t.Errorf("expected new access and refresh cookies, got %v", set)
		}
	})
}

func TestOptionalAuthMiddleware(t *testing.T) {
	app, userID := newApp(t, cachedummy.New())
	cookies := login(t, app)

	t.Run("anonymous request reaches the handler without a user", func(t *testing.T) {
		got, status, _ := serve(t, app.Middleware.OptionalAuthMidware)
		if status != http.StatusOK {
			t.Errorf("status %d, want 200", status)
		}
		if got != nil {
			t.Errorf("anonymous request was given user %d", *got)
		}
	})

	t.Run("invalid tokens reach the handler without a user", func(t *testing.T) {
		bogus := &http.Cookie{Name: setup.REFRESH_TOKEN_NAME, Value: "not-a-session"}
		if got, status, _ := serve(t, app.Middleware.OptionalAuthMidware, bogus); status != http.StatusOK || got != nil {
			t.Errorf("status %d, user %v; want 200 and no user", status, got)
		}
	})

	t.Run("logged in request gets the user", func(t *testing.T) {
		got, _, _ := serve(t, app.Middleware.OptionalAuthMidware, cookies.AccessToken, cookies.RefreshToken)
		if got == nil || *got != userID {
			t.Errorf("handler saw user %v, want %d", got, userID)
		}
	})
}
