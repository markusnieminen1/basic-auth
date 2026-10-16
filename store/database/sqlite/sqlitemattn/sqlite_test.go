package sqlitemattn_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/service"
	"github.com/markusnieminen1/basic-auth/store/database/sqlite"
	"github.com/markusnieminen1/basic-auth/store/database/sqlite/sqlitemattn"
	"github.com/markusnieminen1/basic-auth/store/session"
	sessionsqlite "github.com/markusnieminen1/basic-auth/store/session/sqlite"
	"github.com/markusnieminen1/basic-auth/store/user"
	usersqlite "github.com/markusnieminen1/basic-auth/store/user/sqlite"

	_ "github.com/mattn/go-sqlite3"
)

var ctx = context.Background()

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sqlitemattn.Open(ctx, filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newUser(t *testing.T, repo user.Repository, name string) int64 {
	t.Helper()
	id, err := repo.Create(ctx, sharedmodels.AllUserProfileAuthData{Username: name, Email: name + "@example.com", PasswordHash: "hash-" + name})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	for i := 0; i < 2; i++ {
		db, err := sqlitemattn.Open(ctx, path)
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		db.Close()
	}
}

func TestUserRepository(t *testing.T) {
	repo := usersqlite.New(openDB(t))
	id := newUser(t, repo, "alice")

	got, err := repo.GetByUsername(ctx, "alice")
	if err != nil || got.UserID != id || got.PasswordHash != "hash-alice" {
		t.Fatalf("GetByUsername = %+v, %v", got, err)
	}
	if limited, err := repo.GetByID(ctx, id); err != nil || limited.Email != "alice@example.com" {
		t.Fatalf("GetByID = %+v, %v", limited, err)
	}

	if _, err := repo.GetByID(ctx, 999); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("GetByID missing = %v, want ErrNotFound", err)
	}
	if _, err := repo.GetByUsername(ctx, "nobody"); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("GetByUsername missing = %v, want ErrNotFound", err)
	}

	_, err = repo.Create(ctx, sharedmodels.AllUserProfileAuthData{Username: "alice", Email: "other@example.com", PasswordHash: "x"})
	if !errors.Is(err, user.ErrUsernameTaken) {
		t.Errorf("duplicate username = %v, want ErrUsernameTaken", err)
	}
	_, err = repo.Create(ctx, sharedmodels.AllUserProfileAuthData{Username: "other", Email: "alice@example.com", PasswordHash: "x"})
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Errorf("duplicate email = %v, want ErrEmailTaken", err)
	}
}

func TestUserRepositoryUpdatesAndDelete(t *testing.T) {
	repo := usersqlite.New(openDB(t))
	id := newUser(t, repo, "alice")
	newUser(t, repo, "bob")

	if err := repo.UpdateEmail(ctx, id, "new@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateUsername(ctx, id, "alice2"); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdatePasswordHash(ctx, id, "hash2"); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.GetCredentialsByID(ctx, id)
	if got.Email != "new@example.com" || got.Username != "alice2" || got.PasswordHash != "hash2" {
		t.Errorf("after updates: %+v", got)
	}

	if err := repo.UpdateUsername(ctx, id, "bob"); !errors.Is(err, user.ErrUsernameTaken) {
		t.Errorf("rename to taken = %v, want ErrUsernameTaken", err)
	}
	if err := repo.UpdateEmail(ctx, id, "bob@example.com"); !errors.Is(err, user.ErrEmailTaken) {
		t.Errorf("email to taken = %v, want ErrEmailTaken", err)
	}
	if err := repo.UpdateEmail(ctx, 999, "x@example.com"); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("update missing = %v, want ErrNotFound", err)
	}

	if err := repo.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := repo.Delete(ctx, id); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("second delete = %v, want ErrNotFound", err)
	}
}

func TestSessionRepository(t *testing.T) {
	db := openDB(t)
	users := usersqlite.New(db)
	sessions := sessionsqlite.New(db)
	id := newUser(t, users, "alice")

	valid := session.Session{UserID: id, RefreshTokenHash: "h1", ValidUntil: time.Now().Add(time.Hour)}
	if err := sessions.Create(ctx, valid); err != nil {
		t.Fatal(err)
	}
	got, err := sessions.GetByTokenHash(ctx, "h1")
	if err != nil || got.UserID != id {
		t.Fatalf("GetByTokenHash = %+v, %v", got, err)
	}

	if _, err = sessions.GetByTokenHash(ctx, "unknown"); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("unknown = %v, want ErrNotFound", err)
	}
	expired := session.Session{UserID: id, RefreshTokenHash: "h2", ValidUntil: time.Now().Add(-time.Minute)}
	if err = sessions.Create(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.GetByTokenHash(ctx, "h2"); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("expired = %v, want ErrNotFound", err)
	}

	if revoked, err := sessions.Revoke(ctx, "h1"); err != nil || !revoked {
		t.Fatalf("first Revoke = %v, %v; want true", revoked, err)
	}
	if revoked, err := sessions.Revoke(ctx, "h1"); err != nil || revoked {
		t.Errorf("second Revoke = %v, %v; want false and no error", revoked, err)
	}

	for i := 0; i < 3; i++ {
		s := session.Session{UserID: id, RefreshTokenHash: fmt.Sprintf("device-%d", i), ValidUntil: time.Now().Add(time.Hour)}
		if err = sessions.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err = sessions.RevokeAllForUser(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.GetByTokenHash(ctx, "device-1"); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("after RevokeAllForUser = %v, want ErrNotFound", err)
	}
}

// The application may open its own *sql.DB without PRAGMA foreign_keys. Deleting a user
// must still remove their sessions.
func TestDeleteUserRemovesSessionsWithoutForeignKeys(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "plain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = sqlite.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	users, sessions := usersqlite.New(db), sessionsqlite.New(db)
	id := newUser(t, users, "alice")
	if err = sessions.Create(ctx, session.Session{UserID: id, RefreshTokenHash: "h1", ValidUntil: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err = users.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.GetByTokenHash(ctx, "h1"); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("session survived user deletion: %v", err)
	}
}

func TestConcurrentWritesDoNotLockTheDatabase(t *testing.T) {
	repo := usersqlite.New(openDB(t))
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("user%d", i)
			_, err := repo.Create(ctx, sharedmodels.AllUserProfileAuthData{Username: name, Email: name + "@example.com", PasswordHash: "h"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent create: %v", err)
		}
	}
}

// fakeHasher keeps the test free of a real hashing component.
type fakeHasher struct{}

func (fakeHasher) Hash(plain string) (string, error) { return "hashed:" + plain, nil }
func (fakeHasher) Verify(plain, hash string) (bool, error) {
	return strings.TrimPrefix(hash, "hashed:") == plain, nil
}

func TestAccountChangesRequireThePassword(t *testing.T) {
	db := openDB(t)
	accounts, err := service.NewAccountManagerService(usersqlite.New(db), sessionsqlite.New(db), fakeHasher{})
	if err != nil {
		t.Fatal(err)
	}
	created, err := accounts.Register(ctx, sharedmodels.RegisterInput{Email: "alice@example.com", Username: "alice", Password: "Sup3r-secret!"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = accounts.UpdateEmail(ctx, sharedmodels.UpdateEmailInput{UserID: created.UserID, Email: "new@example.com", Password: "wrong"})
	if err == nil {
		t.Fatal("email changed with the wrong password")
	}
	_, err = accounts.UpdateUsername(ctx, sharedmodels.UpdateUsernameInput{UserID: created.UserID, Username: "alice2", Password: "wrong"})
	if err == nil {
		t.Fatal("username changed with the wrong password")
	}

	updated, err := accounts.UpdateEmail(ctx, sharedmodels.UpdateEmailInput{UserID: created.UserID, Email: "new@example.com", Password: "Sup3r-secret!"})
	if err != nil || updated.Email != "new@example.com" {
		t.Fatalf("UpdateEmail = %+v, %v", updated, err)
	}
	updated, err = accounts.UpdateUsername(ctx, sharedmodels.UpdateUsernameInput{UserID: created.UserID, Username: "alice2", Password: "Sup3r-secret!"})
	if err != nil || updated.Username != "alice2" {
		t.Fatalf("UpdateUsername = %+v, %v", updated, err)
	}
}
