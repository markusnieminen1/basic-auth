package database

import "errors"

var (
	// ErrNotImplemented is returned by placeholder components, so that a config that selects one fails loudly.
	ErrNotImplemented = errors.New("not implemented.")

	ErrOpenDbFail = errors.New("failed to open auth database.")
	ErrInitDbFail = errors.New("failed to create auth tables.")

	// ErrIncompatibleSchema means an existing table cannot be migrated in place, for example
	// a users table without a user_id column. Fix or rename the table, or use another database.
	ErrIncompatibleSchema = errors.New("existing database schema is incompatible with auth.")
)
