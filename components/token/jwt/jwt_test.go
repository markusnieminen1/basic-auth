package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/markusnieminen1/basic-auth/components/token"
)

var ctx = context.Background()

// b64 is how JWT segments are encoded, for building tokens by hand.
var b64 = base64.RawURLEncoding

func newAccess(t *testing.T) *Access {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewEdDSALogic(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func wantInvalid(t *testing.T, s *Access, rawToken, what string) {
	t.Helper()
	if _, err := s.Validate(ctx, rawToken); !errors.Is(err, token.ErrInvalidToken) {
		t.Errorf("%s: got %v, want ErrInvalidToken", what, err)
	}
}

// sign builds a token from raw JSON segments, correctly signed by the strategy's key.
func sign(s *Access, headerJSON, claimsJSON string) string {
	input := b64.EncodeToString([]byte(headerJSON)) + "." + b64.EncodeToString([]byte(claimsJSON))
	return input + "." + b64.EncodeToString(ed25519.Sign(s.key, []byte(input)))
}

const header = `{"alg":"EdDSA","typ":"JWT"}`

func TestRoundTrip(t *testing.T) {
	s := newAccess(t)
	raw, expiresAt, err := s.Issue(ctx, 42, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Validate(ctx, raw)
	if err != nil || got != 42 {
		t.Fatalf("Validate = %d, %v; want 42", got, err)
	}
	if d := time.Until(expiresAt); d < 55*time.Second || d > time.Minute {
		t.Errorf("returned expiry is %v away, want about a minute", d)
	}
}

func TestEveryTokenIsUnique(t *testing.T) {
	s := newAccess(t)
	a, _, _ := s.Issue(ctx, 1, time.Minute)
	b, _, _ := s.Issue(ctx, 1, time.Minute)
	if a == b {
		t.Error("two tokens issued for the same user in the same second are identical; revoking one would revoke both")
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	s := newAccess(t)
	raw, _, _ := s.Issue(ctx, 7, -time.Minute)
	wantInvalid(t, s, raw, "token issued with a negative ttl")
}

func TestTamperingIsRejected(t *testing.T) {
	s := newAccess(t)
	raw, _, _ := s.Issue(ctx, 1, time.Minute)
	parts := strings.Split(raw, ".")

	// Swap in a payload for another user while keeping the old signature.
	forged := `{"sub":"2","iat":1,"exp":9999999999,"jti":"x"}`
	wantInvalid(t, s, parts[0]+"."+b64.EncodeToString([]byte(forged))+"."+parts[2], "forged payload")
	wantInvalid(t, s, parts[0]+"."+parts[1]+"."+parts[2][:len(parts[2])-2]+"AA", "damaged signature")
	wantInvalid(t, s, parts[0]+"."+parts[1]+".", "empty signature")
	wantInvalid(t, newAccess(t), raw, "token signed with another key")
}

func TestAlgorithmAttacks(t *testing.T) {
	s := newAccess(t)
	claims := `{"sub":"1","iat":1,"exp":9999999999,"jti":"x"}`

	none := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64.EncodeToString([]byte(claims)) + "."
	wantInvalid(t, s, none, "alg none without signature")
	wantInvalid(t, s, sign(s, `{"alg":"none","typ":"JWT"}`, claims), "alg none with a signature")
	wantInvalid(t, s, sign(s, `{"alg":"eddsa","typ":"JWT"}`, claims), "alg in another case")
	wantInvalid(t, s, sign(s, `{"typ":"JWT"}`, claims), "missing alg")

	// Classic confusion: an HMAC token keyed with the public key must not be accepted.
	input := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + b64.EncodeToString([]byte(claims))
	mac := hmac.New(sha256.New, s.key.Public().(ed25519.PublicKey))
	mac.Write([]byte(input))
	wantInvalid(t, s, input+"."+b64.EncodeToString(mac.Sum(nil)), "HS256 token keyed with the public key")
}

func TestMalformedInput(t *testing.T) {
	s := newAccess(t)
	valid, _, _ := s.Issue(ctx, 1, time.Minute)
	for name, raw := range map[string]string{
		"empty":            "",
		"one part":         "abc",
		"two parts":        "a.b",
		"four parts":       valid + ".extra",
		"not base64":       "!!!.@@@.###",
		"header not json":  b64.EncodeToString([]byte("nope")) + ".e30.AAAA",
		"padded base64url": strings.Replace(valid, ".", "=.", 1),
	} {
		wantInvalid(t, s, raw, name)
	}
}

func TestClaimRules(t *testing.T) {
	s := newAccess(t)
	wantInvalid(t, s, sign(s, header, `{"sub":"1","iat":1}`), "no exp claim")
	wantInvalid(t, s, sign(s, header, `{"sub":"abc","iat":1,"exp":9999999999}`), "non-numeric subject")
	wantInvalid(t, s, sign(s, header, `{"iat":1,"exp":9999999999}`), "no subject")
	wantInvalid(t, s, sign(s, header, `{"sub":"1","exp":"soon"}`), "exp of the wrong type")
	if _, err := s.Validate(ctx, sign(s, header, `{"sub":"1","iat":1,"exp":9999999999}`)); err != nil {
		t.Errorf("well-formed hand-made token rejected: %v", err)
	}
}

func TestConstructorRejectsBadKey(t *testing.T) {
	if _, err := NewEdDSALogic(ed25519.PrivateKey("short")); err == nil {
		t.Error("short Ed25519 private key accepted")
	}
}
