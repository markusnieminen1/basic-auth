// Package sqlite holds the sqlite schema and the migration for it.
//
// It does not import a sqlite driver. The application opens the *sql.DB with the
// driver it prefers (mattn/go-sqlite3, modernc.org/sqlite, ...), runs Migrate once
// at startup, and hands the same *sql.DB to the sqlite user and session repositories.
// The application owns the *sql.DB and closes it.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/markusnieminen1/basic-auth/store/database"
)

//go:embed schema/default.sql
var defaultSchema string

// Migrate creates the auth tables if they do not exist. It is idempotent.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return database.ErrOpenDbFail
	}
	if _, err := db.ExecContext(ctx, defaultSchema); err != nil {
		return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
	}
	return nil
}
