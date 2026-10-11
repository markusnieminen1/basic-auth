package dummy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/markusnieminen1/basic-auth/components/caching"
)

var ctx = context.Background()

func TestStoreContract(t *testing.T) {
	s := New()

	if _, err := s.Get(ctx, "missing"); !errors.Is(err, caching.ErrMiss) {
		t.Errorf("missing key = %v, want ErrMiss", err)
	}

	if err := s.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, "k"); err != nil || string(got) != "v" {
		t.Errorf("Get = %q, %v", got, err)
	}

	// A non-positive ttl stores nothing, and overwrites nothing that was there.
	if err := s.Set(ctx, "k", []byte("v2"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, caching.ErrMiss) {
		t.Errorf("ttl 0 entry = %v, want ErrMiss", err)
	}

	if err := s.Set(ctx, "short", []byte("v"), 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := s.Get(ctx, "short"); !errors.Is(err, caching.ErrMiss) {
		t.Errorf("expired entry = %v, want ErrMiss", err)
	}

	if err := s.Delete(ctx, "never-existed"); err != nil {
		t.Errorf("deleting a missing key must not fail: %v", err)
	}
}

func TestStoreCopiesValues(t *testing.T) {
	s := New()
	value := []byte("abc")
	_ = s.Set(ctx, "k", value, time.Minute)
	value[0] = 'X'

	got, _ := s.Get(ctx, "k")
	got[1] = 'Y'
	again, _ := s.Get(ctx, "k")
	if string(again) != "abc" {
		t.Errorf("stored value was modified through a slice: %q", again)
	}
}
