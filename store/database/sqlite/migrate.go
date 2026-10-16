package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/markusnieminen1/basic-auth/store/database"
)

//go:embed schema/tables.sql
var tablesSQL string

//go:embed schema/indexes.sql
var indexesSQL string

// column is a column a table must have. definition is what follows the name in ALTER TABLE
// ... ADD COLUMN, so it needs a default: sqlite cannot add a NOT NULL column without one.
type column struct {
	name       string
	definition string
}

// tableSpec describes one table of the schema. key is the integer primary key. It cannot be
// added to an existing table, so a table without it is rejected. columns are everything else.
type tableSpec struct {
	name    string
	key     string
	columns []column
}

// tables must match schema/tables.sql, which TestTablesMatchSchema checks.
var tables = []tableSpec{
	{name: "users", key: "user_id", columns: []column{
		{"username", "TEXT NOT NULL DEFAULT ''"},
		{"email", "TEXT NOT NULL DEFAULT ''"},
		{"pwd_hash", "TEXT NOT NULL DEFAULT ''"},
	}},
	{name: "user_sessions", key: "session_id", columns: []column{
		{"user_id", "INTEGER NOT NULL DEFAULT 0"},
		{"refresh_token", "TEXT NOT NULL DEFAULT ''"},
		{"valid_until", "TEXT NOT NULL DEFAULT ''"},
	}},
	{name: "path_permissions", columns: []column{
		{"user_id", "INTEGER NOT NULL DEFAULT 0"},
		{"path", "TEXT NOT NULL DEFAULT ''"},
	}},
	{name: "ops_permissions", columns: []column{
		{"user_id", "INTEGER NOT NULL DEFAULT 0"},
		{"operation", "TEXT NOT NULL DEFAULT ''"},
	}},
	{name: "events", key: "event_id", columns: []column{
		{"ip", "TEXT NOT NULL DEFAULT ''"},
		{"event", "TEXT NOT NULL DEFAULT ''"},
		{"user_id", "INTEGER"},
	}},
	{name: "audit", key: "audit_id", columns: []column{
		{"ip", "TEXT NOT NULL DEFAULT ''"},
		{"event", "TEXT NOT NULL DEFAULT ''"},
		{"user_id", "INTEGER"},
	}},
}

// Migrate makes db fit the auth schema and is safe to run on every start. It works on a
// database that already holds some or all of the tables:
//
//   - missing tables are created
//   - missing columns are added to existing tables, with an empty default for existing rows
//   - missing indexes are created, and fail if existing rows break a unique index
//
// Nothing is dropped or rewritten, so extra tables and columns of the application are left alone.
// A table that has no usable primary key column (see tableSpec.key) is reported as
// database.ErrIncompatibleSchema, since it cannot be repaired in place.
// Everything runs in one transaction, so a failed migration changes nothing.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return database.ErrOpenDbFail
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
	}
	defer tx.Rollback()

	// Existing tables have to be inspected before the schema is applied: the
	// definition of a new table says nothing about one that was there already.
	existing := make(map[string]map[string]bool, len(tables))
	for _, spec := range tables {
		cols, err := columnsOf(ctx, tx, spec.name)
		if err != nil {
			return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
		}
		existing[spec.name] = cols
	}

	if _, err = tx.ExecContext(ctx, tablesSQL); err != nil {
		return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
	}
	for _, spec := range tables {
		if err = addMissingColumns(ctx, tx, spec, existing[spec.name]); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, indexesSQL); err != nil {
		return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("%w: %v", database.ErrInitDbFail, err)
	}
	return nil
}

// addMissingColumns brings one table that existed before this migration up to spec.
// have is nil for a table that did not exist, which tables.sql has just created complete.
func addMissingColumns(ctx context.Context, tx *sql.Tx, spec tableSpec, have map[string]bool) error {
	if len(have) == 0 {
		return nil
	}
	if spec.key != "" && !have[spec.key] {
		return fmt.Errorf("%w: table %s has no %s column", database.ErrIncompatibleSchema, spec.name, spec.key)
	}
	for _, col := range spec.columns {
		if have[col.name] {
			continue
		}
		// Names come from the constant table above, never from input.
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", spec.name, col.name, col.definition)
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%w: add %s.%s: %v", database.ErrInitDbFail, spec.name, col.name, err)
		}
	}
	return nil
}

// columnsOf returns the column names of table, or an empty set if the table does not exist.
func columnsOf(ctx context.Context, tx *sql.Tx, table string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := make(map[string]bool)
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}
