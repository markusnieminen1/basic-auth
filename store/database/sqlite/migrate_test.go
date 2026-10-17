package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/markusnieminen1/basic-auth/store/database"
)

var ctx = context.Background()

func openRaw(t *testing.T, setupSQL string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if setupSQL != "" {
		if _, err = db.Exec(setupSQL); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func columnNames(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	return names
}

// The column lists in migrate.go are what existing tables are repaired to, so they must
// describe exactly the tables that schema/tables.sql creates.
func TestTablesMatchSchema(t *testing.T) {
	db := openRaw(t, tablesSQL)
	for _, spec := range tables {
		want := append([]string{}, spec.columnNames()...)
		got := columnNames(t, db, spec.name)
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(want, got) {
			t.Errorf("%s: tables.sql has columns %v, migrate.go lists %v", spec.name, got, want)
		}
	}
}

func (s tableSpec) columnNames() []string {
	var names []string
	if s.key != "" {
		names = append(names, s.key)
	}
	for _, c := range s.columns {
		names = append(names, c.name)
	}
	return names
}

func TestMigrateFreshDatabaseIsIdempotent(t *testing.T) {
	db := openRaw(t, "")
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, db); err != nil {
			t.Fatalf("run #%d: %v", i, err)
		}
	}
	for _, spec := range tables {
		if len(columnNames(t, db, spec.name)) != len(spec.columnNames()) {
			t.Errorf("%s was not created complete", spec.name)
		}
	}
}

func TestMigrateAddsMissingColumnsAndKeepsData(t *testing.T) {
	db := openRaw(t, `
		CREATE TABLE users (user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, signup_source TEXT);
		INSERT INTO users (username, signup_source) VALUES ('alice', 'legacy'), ('bob', 'legacy');
		CREATE TABLE user_sessions (session_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL);
		INSERT INTO user_sessions (user_id) VALUES (1);`)

	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	for table, want := range map[string][]string{
		"users":         {"user_id", "username", "email", "pwd_hash", "signup_source"},
		"user_sessions": {"session_id", "user_id", "refresh_token", "valid_until"},
	} {
		got := columnNames(t, db, table)
		for _, name := range want {
			if !slices.Contains(got, name) {
				t.Errorf("%s lacks column %s after migration, has %v", table, name, got)
			}
		}
	}

	var source string
	if err := db.QueryRow(`SELECT signup_source FROM users WHERE username = 'bob'`).Scan(&source); err != nil || source != "legacy" {
		t.Errorf("existing data should be untouched, got %q (err %v)", source, err)
	}

	// Existing rows share the empty email, which must not block the unique index,
	// but real values are still unique.
	if _, err := db.Exec(`INSERT INTO users (username, email, pwd_hash) VALUES ('carol', 'c@example.com', 'h')`); err != nil {
		t.Fatal(err)
	}
	_, err := db.Exec(`INSERT INTO users (username, email, pwd_hash) VALUES ('dave', 'c@example.com', 'h')`)
	if err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed: users.email") {
		t.Errorf("duplicate email should violate the unique index, got %v", err)
	}

	if err = Migrate(ctx, db); err != nil {
		t.Errorf("second run: %v", err)
	}
}

func TestMigrateRejectsTableWithoutKey(t *testing.T) {
	db := openRaw(t, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)`)
	err := Migrate(ctx, db)
	if !errors.Is(err, database.ErrIncompatibleSchema) {
		t.Fatalf("got %v, want ErrIncompatibleSchema", err)
	}
	if got := columnNames(t, db, "users"); slices.Contains(got, "email") {
		t.Errorf("a failed migration must not change the database, users has %v", got)
	}
	if got := columnNames(t, db, "user_sessions"); len(got) != 0 {
		t.Errorf("a failed migration must not create tables, user_sessions has %v", got)
	}
}

func TestMigrateFailsOnDuplicatesForUniqueIndex(t *testing.T) {
	db := openRaw(t, `
		CREATE TABLE users (user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, pwd_hash TEXT);
		INSERT INTO users (username, email, pwd_hash) VALUES ('alice', 'a@example.com', 'h'), ('alice', 'b@example.com', 'h');`)
	if err := Migrate(ctx, db); !errors.Is(err, database.ErrInitDbFail) {
		t.Fatalf("got %v, want ErrInitDbFail", err)
	}
}

func TestMigrateNilDB(t *testing.T) {
	if err := Migrate(ctx, nil); !errors.Is(err, database.ErrOpenDbFail) {
		t.Fatalf("got %v", err)
	}
}
