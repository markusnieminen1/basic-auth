// Package dummy is an in-memory caching.Store for development and tests.
//
// It is only valid inside one process, and expired entries are removed when they
// are read, so entries that are never read stay in memory.
package dummy

import (
	"context"
	"sync"
	"time"

	"github.com/markusnieminen1/basic-auth/components/caching"
)

type entry struct {
	value     []byte
	expiresAt time.Time
}

type Store struct {
	mu      sync.Mutex
	entries map[string]entry
}

func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		return nil, caching.ErrMiss
	}
	if !time.Now().Before(e.expiresAt) {
		delete(s.entries, key)
		return nil, caching.ErrMiss
	}
	return append([]byte(nil), e.value...), nil
}

func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ttl <= 0 {
		delete(s.entries, key)
		return nil
	}
	s.entries[key] = entry{value: append([]byte(nil), value...), expiresAt: time.Now().Add(ttl)}
	return nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)
	return nil
}

var _ caching.Store = (*Store)(nil)

func New() *Store {
	return &Store{entries: make(map[string]entry)}
}
