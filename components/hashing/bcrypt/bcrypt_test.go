package bcrypt_test

import (
	"strings"
	"testing"

	"github.com/markusnieminen1/basic-auth/components/hashing/bcrypt"
)

// Minimum cost keeps the tests fast. Production uses DefaultCost.
func newHasher(t *testing.T) *bcrypt.Hasher {
	t.Helper()
	h, err := bcrypt.New(bcrypt.WithCost(4))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashAndVerify(t *testing.T) {
	h := newHasher(t)
	hash, err := h.Hash("Sup3r-secret!")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("not a bcrypt hash: %q", hash)
	}

	if ok, err := h.Verify("Sup3r-secret!", hash); err != nil || !ok {
		t.Errorf("correct password: %v, %v", ok, err)
	}
	if ok, err := h.Verify("wrong", hash); err != nil || ok {
		t.Errorf("wrong password must be (false, nil), got %v, %v", ok, err)
	}
	if ok, err := h.Verify("anything", "not-a-bcrypt-hash"); err == nil || ok {
		t.Errorf("malformed hash must be an error, got %v, %v", ok, err)
	}
}

func TestHashesAreSalted(t *testing.T) {
	h := newHasher(t)
	a, _ := h.Hash("same password")
	b, _ := h.Hash("same password")
	if a == b {
		t.Error("the same password produced the same hash, so there is no salt")
	}
}

func TestLongPasswordIsRejectedNotTruncated(t *testing.T) {
	h := newHasher(t)
	if _, err := h.Hash(strings.Repeat("a", 73)); err == nil {
		t.Error("a password over 72 bytes was hashed, bcrypt would silently ignore the tail")
	}
}

func TestCostOption(t *testing.T) {
	for _, cost := range []int{3, 32} {
		if _, err := bcrypt.New(bcrypt.WithCost(cost)); err == nil {
			t.Errorf("cost %d accepted", cost)
		}
	}
	if _, err := bcrypt.New(); err != nil {
		t.Errorf("default cost rejected: %v", err)
	}
}
