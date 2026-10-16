// Package sqlitemattn mattn/go-sqlite3 driver
package sqlitemattn

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/markusnieminen1/basic-auth/store/database"
	"github.com/markusnieminen1/basic-auth/store/database/sqlite"
	_ "github.com/mattn/go-sqlite3"
)

// Open opens (creating if needed) the database
func Open(ctx context.Context, path string) (*sql.DB, error) {
	query := url.Values{}
	query.Set("_foreign_keys", "on")
	query.Set("_busy_timeout", "5000")

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
