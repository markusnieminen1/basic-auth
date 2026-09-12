package sqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"

	"github.com/markusnieminen1/basic-auth/repository/customerrors"
	_ "github.com/mattn/go-sqlite3"
)

// The caller is responsible to close the connection
// Use:
//
//	defer db.close()
func SetupDB() (db *sql.DB, err error) {
	db, err = sql.Open("sqlite3", "auth.db?_foreign_keys=on")
	if err != nil {
		return nil, customerrors.ErrOpenDbFail
	}

	if err = db.Ping(); err != nil {
		db.Close()
		return nil, customerrors.ErrOpenDbFail
	}

	// Resolve file location
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		db.Close()
		return nil, customerrors.ErrOpenDbFail
	}

	sqlSchemaPath := filepath.Join(filepath.Dir(filename), "..", "schema", "default.sql")

	schemaBytes, err := os.ReadFile(sqlSchemaPath)
	if err != nil {
		db.Close()
		return nil, customerrors.ErrOpenDbFail
	}

	if _, err = db.Exec(string(schemaBytes)); err != nil {
		db.Close()
		return nil, customerrors.ErrOpenDbFail
	}

	return db, nil
}
