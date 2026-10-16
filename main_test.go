package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/markusnieminen1/basic-auth/components/caching"
	cachedummy "github.com/markusnieminen1/basic-auth/components/caching/dummy"
	"github.com/markusnieminen1/basic-auth/components/hashing/bcrypt"
	hashdummy "github.com/markusnieminen1/basic-auth/components/hashing/dummy"
	tokendummy "github.com/markusnieminen1/basic-auth/components/token/dummy"
	"github.com/markusnieminen1/basic-auth/components/token/jwt"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/handlers"
	"github.com/markusnieminen1/basic-auth/setup"
	"github.com/markusnieminen1/basic-auth/store/database/sqlite/sqlitemattn"
	sessionsqlite "github.com/markusnieminen1/basic-auth/store/session/sqlite"
	usersqlite "github.com/markusnieminen1/basic-auth/store/user/sqlite"
)

var ctx = context.Background()

// TestMain lowers the bcrypt cost of the default hasher: the tests only need it to work, not to be slow.
func TestMain(m *testing.M) {
	bcrypt.DefaultCost = 4 // the lowest cost bcrypt accepts
	os.Exit(m.Run())
}

const password = "Sup3r-secret!"

// dummyConfig returns a config where every component is given, so nothing is created in the
// working directory. Users and Sessions are sqlite on a private database in a temporary directory,
// which the sessions' foreign key to the users needs to be the same database.
func dummyConfig(t *testing.T, cache caching.Store) Config {
	t.Helper()
	db, err := sqlitemattn.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return Config{
		Hasher:   hashdummy.New(),
		Access:   tokendummy.NewAccess(),
		Refresh:  tokendummy.NewRefresh(),
		Users:    usersqlite.New(db),
		Sessions: sessionsqlite.New(db),
		Cache:    cache,
	}
}

// newApp wires every component from its dummy and registers the user "alice".
func newApp(t *testing.T, cache caching.Store) (*App, int64) {
	t.Helper()
	app, err := NewAuthApp(dummyConfig(t, cache))
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

// TestNewDefaults builds the app from an empty config: bcrypt, an Ed25519 key file,
// and sqlite, all created in the working directory.
func TestNewDefaults(t *testing.T) {
	t.Chdir(t.TempDir())

	app, err := NewAuthApp(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: "alice@example.com", Username: "alice", Password: password}); err != nil {
		t.Fatal(err)
	}
	cookies := login(t, app)
	if _, err = app.Authenticator.Authenticate(ctx, cookies); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{setup.AuthDbDefaultPath, jwt.DefaultKeyFile} {
		if _, err = os.Stat(file); err != nil {
			t.Errorf("default component should have created %s: %v", file, err)
		}
	}
	if err = app.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestNewOverridesDefaults checks that a component from Config is used instead of its default,
// and that nothing is created on disk for the components that were replaced.
func TestNewOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	app, err := NewAuthApp(dummyConfig(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Errorf("overriding every component should leave the directory empty, got %v (err %v)", entries, err)
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
	if _, err = app.AuthenticationService.Logout(ctx, renewed); err != nil {
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
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := jwt.NewEdDSALogic(key)
	if err != nil {
		t.Fatal(err)
	}

	cfg := dummyConfig(t, cachedummy.New())
	cfg.Access = strategy
	app, err := NewAuthApp(cfg)
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
	if _, err = app.AuthenticationService.Logout(ctx, cookies); err != nil {
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

	if _, err := app.AuthenticationService.Logout(ctx, cookies); err != nil {
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
		got, status, set := serve(t, app.Middleware.RequireAuthRoute, cookies.AccessToken, cookies.RefreshToken)
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
		app.Middleware.RequireAuthRoute(final).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/protected", nil))
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

		got, _, set := serve(t, app.Middleware.RequireAuthRoute, stale, cookies.RefreshToken)
		if got == nil || *got != userID {
			t.Fatalf("handler saw user %v, want %d", got, userID)
		}
		if len(set) != 2 {
			t.Errorf("expected new access and refresh cookies, got %v", set)
		}

		// The refresh token was rotated, so replaying the old one must not authenticate.
		if _, status, _ := serve(t, app.Middleware.RequireAuthRoute, stale, cookies.RefreshToken); status != http.StatusUnauthorized {
			t.Errorf("a replayed refresh token got status %d, want 401", status)
		}
	})

	// A browser deletes the access cookie once it expires, so only the refresh token arrives.
	t.Run("missing access token is renewed from the refresh token", func(t *testing.T) {
		app, userID := newApp(t, cachedummy.New())
		cookies := login(t, app)

		got, _, set := serve(t, app.Middleware.RequireAuthRoute, cookies.RefreshToken)
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
		got, status, _ := serve(t, app.Middleware.OptionalAuthRoute)
		if status != http.StatusOK {
			t.Errorf("status %d, want 200", status)
		}
		if got != nil {
			t.Errorf("anonymous request was given user %d", *got)
		}
	})

	t.Run("invalid tokens reach the handler without a user", func(t *testing.T) {
		bogus := &http.Cookie{Name: setup.REFRESH_TOKEN_NAME, Value: "not-a-session"}
		if got, status, _ := serve(t, app.Middleware.OptionalAuthRoute, bogus); status != http.StatusOK || got != nil {
			t.Errorf("status %d, user %v; want 200 and no user", status, got)
		}
	})

	t.Run("logged in request gets the user", func(t *testing.T) {
		got, _, _ := serve(t, app.Middleware.OptionalAuthRoute, cookies.AccessToken, cookies.RefreshToken)
		if got == nil || *got != userID {
			t.Errorf("handler saw user %v, want %d", got, userID)
		}
	})
}

func TestConfigTestPassesAndLeavesTheAppDatabaseAlone(t *testing.T) {
	t.Chdir(t.TempDir())

	app, err := NewAuthApp(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	if err = app.ConfigTest(ctx); err != nil {
		t.Fatal(err)
	}
	// Nothing from the test may show up in the app's own database.
	if _, err = app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: configTestUsername, Password: configTestNewPass}); err == nil {
		t.Error("the config test user leaked into the app database")
	}
	if _, err = app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: configTestEmail, Username: configTestUsername, Password: configTestPassword}); err != nil {
		t.Errorf("the app database should not hold the test user, register failed: %v", err)
	}
	// The test can run again and again.
	if err = app.ConfigTest(ctx); err != nil {
		t.Errorf("second run: %v", err)
	}
}

func TestConfigTestWithEveryComponentOverridden(t *testing.T) {
	for name, cache := range map[string]caching.Store{"without cache": nil, "with cache": cachedummy.New()} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			app, err := NewAuthApp(dummyConfig(t, cache))
			if err != nil {
				t.Fatal(err)
			}
			if err = app.ConfigTest(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// brokenHasher accepts every password, which a login check must notice.
type brokenHasher struct{ *hashdummy.Hasher }

func (brokenHasher) Verify(plain, hash string) (bool, error) { return true, nil }

func TestConfigTestCatchesABrokenComponent(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := dummyConfig(t, nil)
	cfg.Hasher = brokenHasher{hashdummy.New()}
	app, err := NewAuthApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = app.ConfigTest(ctx)
	if err == nil || !strings.Contains(err.Error(), "login rejects a wrong password") {
		t.Fatalf("got %v, want the wrong password check to fail", err)
	}
}

// The refresh token in the cookie is a UUID, and the database holds only its hash. Every
// renewal issues a new UUID and replaces the stored hash.
func TestSessionsStoreHashedUUIDs(t *testing.T) {
	t.Chdir(t.TempDir())
	db, err := sqlitemattn.Open(ctx, "sessions.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app, err := NewAuthApp(Config{Hasher: hashdummy.New(), DB: db})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: "alice@example.com", Username: "alice", Password: password}); err != nil {
		t.Fatal(err)
	}

	stored := func() []string {
		rows, err := db.Query(`SELECT refresh_token FROM user_sessions`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var hashes []string
		for rows.Next() {
			var h string
			if err = rows.Scan(&h); err != nil {
				t.Fatal(err)
			}
			hashes = append(hashes, h)
		}
		return hashes
	}
	sha := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	cookies := login(t, app)
	if !uuidPattern.MatchString(cookies.RefreshToken.Value) {
		t.Fatalf("refresh token %q is not a UUID", cookies.RefreshToken.Value)
	}
	if got := stored(); len(got) != 1 || got[0] != sha(cookies.RefreshToken.Value) {
		t.Fatalf("database holds %v, want only the SHA-256 of the UUID", got)
	}

	renewed, err := app.AuthenticationService.Refresh(ctx, cookies)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.RefreshToken.Value == cookies.RefreshToken.Value || !uuidPattern.MatchString(renewed.RefreshToken.Value) {
		t.Fatalf("renewal returned %q, want a new UUID", renewed.RefreshToken.Value)
	}
	if got := stored(); len(got) != 1 || got[0] != sha(renewed.RefreshToken.Value) {
		t.Fatalf("after renewal the database holds %v, want only the hash of the new UUID", got)
	}
}

// Logout over HTTP: the session is gone, and the response carries expired cookies with the
// names and path of the login cookies, which makes the browser overwrite and drop them.
func TestLogoutHandlerOverwritesTheTokens(t *testing.T) {
	app, _ := newApp(t, cachedummy.New())
	loginHandler := &handlers.LoginHandler{AuthenticationService: app.AuthenticationService}
	logoutHandler := &handlers.LogoutHandler{AuthenticationService: app.AuthenticationService}

	body := strings.NewReader(`{"login_username":"alice","login_password":"` + password + `"}`)
	rec := httptest.NewRecorder()
	loginHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/login", body))
	issued := rec.Result().Cookies()
	for _, c := range issued {
		if c.SameSite != http.SameSiteStrictMode || !c.HttpOnly || c.Path != "/" {
			t.Errorf("cookie %s: SameSite %v, HttpOnly %v, Path %q", c.Name, c.SameSite, c.HttpOnly, c.Path)
		}
	}
	if len(issued) != 2 {
		t.Fatalf("login set %d cookies, want 2", len(issued))
	}

	// The browser sends back name and value only.
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	for _, c := range issued {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec = httptest.NewRecorder()
	logoutHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout answered %d", rec.Code)
	}

	cleared := rec.Result().Cookies()
	if len(cleared) != 2 {
		t.Fatalf("logout set %d cookies, want 2", len(cleared))
	}
	for _, c := range cleared {
		var login *http.Cookie
		for _, i := range issued {
			if i.Name == c.Name {
				login = i
			}
		}
		if login == nil || c.Value != "" || c.MaxAge >= 0 || c.Path != login.Path {
			t.Errorf("cookie %+v does not overwrite and expire the login cookie %+v", c, login)
		}
	}

	// The tokens that were sent no longer work.
	stale := sharedmodels.AuthCookies{AccessToken: issued[0], RefreshToken: issued[1]}
	if issued[0].Name == setup.REFRESH_TOKEN_NAME {
		stale = sharedmodels.AuthCookies{AccessToken: issued[1], RefreshToken: issued[0]}
	}
	if _, err := app.Authenticator.Authenticate(ctx, stale); err == nil {
		t.Error("access token still valid after logout, although the request cookie had no expiry")
	}
	if _, err := app.AuthenticationService.Refresh(ctx, stale); err == nil {
		t.Error("refresh token still valid after logout")
	}

	// Anonymous and wrong method requests.
	rec = httptest.NewRecorder()
	logoutHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("anonymous logout answered %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	logoutHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logout", nil))
	if rec.Code == http.StatusOK {
		t.Error("GET /logout should be refused")
	}
}

func post(h http.Handler, target, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, strings.NewReader(body)))
	return rec
}

// Every failure gets the status that fits it, and internal errors never reach the client.
func TestHandlersAnswerWithFittingStatuses(t *testing.T) {
	app, _ := newApp(t, nil)
	register := &handlers.RegisterHandler{AccountService: app.AccountService}
	loginH := &handlers.LoginHandler{AuthenticationService: app.AuthenticationService}

	body := func(email, username string) string {
		return `{"register_email":"` + email + `","register_username":"` + username + `","register_password":"` + password + `"}`
	}
	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"created":        {body("bob@example.com", "bob"), http.StatusCreated},
		"username taken": {body("other@example.com", "alice"), http.StatusConflict},
		"email taken":    {body("alice@example.com", "carol"), http.StatusConflict},
		"invalid email":  {body("not-an-email", "dave"), http.StatusBadRequest},
		"display name":   {body("Eve <eve@example.com>", "eve"), http.StatusBadRequest},
		"bad json":       {`{`, http.StatusBadRequest},
	} {
		if rec := post(register, "/register", tc.body); rec.Code != tc.want {
			t.Errorf("register, %s: %d, want %d (%s)", name, rec.Code, tc.want, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	register.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/register", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /register answered %d", rec.Code)
	}

	if rec = post(loginH, "/login", `{"login_username":"alice","login_password":"nope"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password answered %d, want 401", rec.Code)
	}

	// A failing database is not the client's fault, and its error text stays private.
	cfg := dummyConfig(t, nil)
	cfg.Users = brokenUsers{usersqlite.New(nil)}
	broken, err := NewAuthApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec = post(&handlers.LoginHandler{AuthenticationService: broken.AuthenticationService}, "/login", `{"login_username":"alice","login_password":"x"}`)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "database is down") {
		t.Errorf("repository failure answered %d %q, want 500 without the cause", rec.Code, rec.Body)
	}
}

type brokenUsers struct{ *usersqlite.Repo }

func (brokenUsers) GetByUsername(context.Context, string) (sharedmodels.AllUserProfileAuthData, error) {
	return sharedmodels.AllUserProfileAuthData{}, errors.New("database is down")
}

func TestRegisterStoresTrimmedNames(t *testing.T) {
	app, _ := newApp(t, nil)
	user, err := app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: " bob@example.com ", Username: " bob ", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "bob" || user.Email != "bob@example.com" {
		t.Errorf("stored %q / %q, want the names without spaces", user.Username, user.Email)
	}
	if _, err = app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "bob", Password: password}); err != nil {
		t.Errorf("cannot log in with the trimmed username: %v", err)
	}
}

// A refresh token is accepted once, even when many requests present it at the same moment.
func TestRefreshTokenWorksOnlyOnceUnderConcurrency(t *testing.T) {
	sqliteDB, err := sqlitemattn.Open(ctx, filepath.Join(t.TempDir(), "race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteDB.Close()

	for name, cfg := range map[string]Config{
		"sqlite": {Hasher: hashdummy.New(), DB: sqliteDB, Cache: cachedummy.New()},
	} {
		t.Run(name, func(t *testing.T) {
			app, err := NewAuthApp(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: "alice@example.com", Username: "alice", Password: password}); err != nil {
				t.Fatal(err)
			}
			cookies := login(t, app)

			const attempts = 20
			var wg sync.WaitGroup
			var succeeded atomic.Int32
			for i := 0; i < attempts; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := app.AuthenticationService.Refresh(ctx, cookies); err == nil {
						succeeded.Add(1)
					}
				}()
			}
			wg.Wait()

			if got := succeeded.Load(); got != 1 {
				t.Errorf("%d of %d concurrent refreshes with the same token succeeded, want exactly 1", got, attempts)
			}
		})
	}
}

// The real bcrypt hasher and the real JWT access tokens, with dummies for the rest.
func TestFullCycleWithBcryptAndJWT(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	access, err := jwt.NewEdDSALogic(key)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := bcrypt.New(bcrypt.WithCost(4))
	if err != nil {
		t.Fatal(err)
	}
	cfg := dummyConfig(t, cachedummy.New())
	cfg.Hasher = hasher
	cfg.Access = access
	app, err := NewAuthApp(cfg)
	if err != nil {
		t.Fatal(err)
	}

	user, err := app.AccountService.Register(ctx, sharedmodels.RegisterInput{Email: "alice@example.com", Username: "alice", Password: "Sup3r-secret!"})
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "alice", Password: "Sup3r-secret!"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := app.Authenticator.Authenticate(ctx, cookies); err != nil || got != user.UserID {
		t.Fatalf("Authenticate = %d, %v; want %d", got, err, user.UserID)
	}

	_, wrong := app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "alice", Password: "Wr0ng-password!"})
	_, unknown := app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "mallory", Password: "Sup3r-secret!"})
	if wrong == nil || unknown == nil || wrong.Error() != unknown.Error() {
		t.Errorf("wrong password and unknown user must fail identically: %v / %v", wrong, unknown)
	}

	if err = app.AccountService.ChangePassword(ctx, sharedmodels.ChangePasswordInput{UserID: user.UserID, Current: "Sup3r-secret!", Replacement: "N3w-secret-pass!"}); err != nil {
		t.Fatal(err)
	}
	if _, err = app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "alice", Password: "Sup3r-secret!"}); err == nil {
		t.Error("the old password still works after ChangePassword")
	}
	if _, err = app.AuthenticationService.Login(ctx, sharedmodels.LoginInput{Username: "alice", Password: "N3w-secret-pass!"}); err != nil {
		t.Errorf("the new password does not work: %v", err)
	}
}
