package caching

import (
	"context"
	"errors"
	"time"
)

// ErrMiss must be returned by Get when the key does not exist or has expired.
var ErrMiss = errors.New("cache miss")

// Store is a key-value cache with per-entry expiry. Delete of a missing key is not an error.
// Set with a ttl <= 0 stores nothing: the entry is already expired.
type Store interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}
