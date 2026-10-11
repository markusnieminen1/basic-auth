// Package mattn opens a sqlite database with the mattn/go-sqlite3 driver (cgo) using
// settings that suit the auth tables, and runs the schema migration.
//
// It is a convenience add-on. Any other driver works too: open the *sql.DB yourself,
// call sqlite.Migrate, and pass the same *sql.DB to the sqlite repositories.
package mattn

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	_ "github.com/mattn/go-sqlite3"

	"github.com/markusnieminen1/basic-auth/store/database"
	"github.com/markusnieminen1/basic-auth/store/database/sqlite"
)

// Open opens (creating if needed) the database file at path and migrates the schema.
// Share the returned *sql.DB between the user and session repositories; the caller closes it.
//
// The pragmas are set in the DSN because they are per connection and database/sql keeps a pool:
//   - foreign_keys: enforce the schema's foreign keys
//   - busy_timeout: wait for a competing write instead of failing with "database is locked"
//   - journal_mode=WAL: readers do not block the writer
func Open(ctx context.Context, path string) (*sql.DB, error) {
	query := url.Values{}
	query.Set("_foreign_keys", "on")
	query.Set("_busy_timeout", "5000")
	query.Set("_journal_mode", "WAL")

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?%s", path, query.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", database.ErrOpenDbFail, err)
	}
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("%w: %v", database.ErrOpenDbFail, err)
	}
	if err = sqlite.Migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
