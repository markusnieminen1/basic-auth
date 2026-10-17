package uuid

import (
	"context"
	"regexp"
	"testing"
	"time"
)

var v4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestIssueReturnsUniqueV4UUIDs(t *testing.T) {
	r := NewRefresh()
	seen := map[string]bool{}

	for range 1000 {
		id, expiresAt, err := r.Issue(context.Background(), time.Hour)

		if err != nil {
			t.Fatal(err)
		}

		if !v4.MatchString(id) {
			t.Fatalf("%q is not a version 4 UUID", id)
		}

		if seen[id] {
			t.Fatalf("%q was issued twice", id)
		}

		seen[id] = true

		if time.Until(expiresAt) > time.Hour || time.Until(expiresAt) < 59*time.Minute {
			t.Fatalf("expiry %v does not match the ttl", expiresAt)
		}
	}
}

func TestHashIsDeterministicAndDoesNotContainTheToken(t *testing.T) {
	r := NewRefresh()
	id, _ := NewUUIDToken()
	a, _ := r.Hash(id)
	b, _ := r.Hash(id)
	other, _ := r.Hash("00000000-0000-4000-8000-000000000000")
	if a != b {
		t.Error("the same UUID must always give the same hash")
	}
	if a == other || a == id || len(a) != 64 {
		t.Errorf("unexpected hash %q", a)
	}
}
