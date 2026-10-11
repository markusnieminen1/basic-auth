package bcrypt_test

import (
	"context"
	"strings"
	"testing"

	"github.com/markusnieminen1/basic-auth"
	cachedummy "github.com/markusnieminen1/basic-auth/components/caching/dummy"
	"github.com/markusnieminen1/basic-auth/components/hashing/bcrypt"
	tokendummy "github.com/markusnieminen1/basic-auth/components/token/dummy"
	"github.com/markusnieminen1/basic-auth/components/token/jwt"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	sessionmemory "github.com/markusnieminen1/basic-auth/store/session/memory"
	userdummy "github.com/markusnieminen1/basic-auth/store/user/dummy"
)

// Minimum cost keeps the tests fast. Production uses DefaultCost.
func newHasher(t *testing.T) *bcrypt.Hasher {
	t.Helper()
	h, err := bcrypt.New(bcrypt.WithCost(4))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashAndVerify(t *testing.T) {
	h := newHasher(t)
	hash, err := h.Hash("Sup3r-secret!")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("not a bcrypt hash: %q", hash)
	}

	if ok, err := h.Verify("Sup3r-secret!", hash); err != nil || !ok {
		t.Errorf("correct password: %v, %v", ok, err)
	}
	if ok, err := h.Verify("wrong", hash); err != nil || ok {
		t.Errorf("wrong password must be (false, nil), got %v, %v", ok, err)
	}
	if ok, err := h.Verify("anything", "not-a-bcrypt-hash"); err == nil || ok {
		t.Errorf("malformed hash must be an error, got %v, %v", ok, err)
	}
}

func TestHashesAreSalted(t *testing.T) {
	h := newHasher(t)
	a, _ := h.Hash("same password")
	b, _ := h.Hash("same password")
	if a == b {
		t.Error("the same password produced the same hash, so there is no salt")
	}
}

func TestLongPasswordIsRejectedNotTruncated(t *testing.T) {
	h := newHasher(t)
	if _, err := h.Hash(strings.Repeat("a", 73)); err == nil {
		t.Error("a password over 72 bytes was hashed, bcrypt would silently ignore the tail")
	}
}

func TestCostOption(t *testing.T) {
	for _, cost := range []int{3, 32} {
		if _, err := bcrypt.New(bcrypt.WithCost(cost)); err == nil {
			t.Errorf("cost %d accepted", cost)
		}
	}
	if _, err := bcrypt.New(); err != nil {
		t.Errorf("default cost rejected: %v", err)
	}
}

// The real hasher and the real JWT strategy, wired through auth.New, with dummies for the rest.
func TestFullCycleWithBcryptAndJWT(t *testing.T) {
	ctx := context.Background()
	access, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	app, err := auth.New(auth.Config{
		Hasher:   newHasher(t),
		Access:   access,
		Refresh:  tokendummy.NewRefresh(),
		Users:    userdummy.New(),
		Sessions: sessionmemory.New(),
		Cache:    cachedummy.New(),
	})
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
