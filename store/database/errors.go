package database

import "errors"

var (
	ErrOpenDbFail = errors.New("failed to open auth database.")
	ErrInitDbFail = errors.New("failed to create auth tables.")
)
