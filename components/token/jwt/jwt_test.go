package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/markusnieminen1/basic-auth/components/token"
)

var ctx = context.Background()

var secret = []byte("0123456789abcdef0123456789abcdef")

func mustHS256(t *testing.T, opts ...Option) *Strategy {
	t.Helper()
	s, err := NewHS256(secret, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustEdDSA(t *testing.T, opts ...Option) (*Strategy, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewEdDSA(priv, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s, pub
}

func wantInvalid(t *testing.T, s *Strategy, rawToken, what string) {
	t.Helper()
	if _, err := s.Validate(ctx, rawToken); !errors.Is(err, token.ErrInvalidToken) {
		t.Errorf("%s: got %v, want ErrInvalidToken", what, err)
	}
}

// forgeHS256 builds a correctly signed HS256 token from raw JSON segments.
func forgeHS256(headerJSON, claimsJSON string) string {
	input := b64.EncodeToString([]byte(headerJSON)) + "." + b64.EncodeToString([]byte(claimsJSON))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + b64.EncodeToString(mac.Sum(nil))
}

func TestRoundTrip(t *testing.T) {
	edSigner, _ := mustEdDSA(t)
	for name, s := range map[string]*Strategy{"HS256": mustHS256(t), "EdDSA": edSigner} {
		t.Run(name, func(t *testing.T) {
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
		})
	}
}

func TestEveryTokenIsUnique(t *testing.T) {
	s := mustHS256(t)
	a, _, _ := s.Issue(ctx, 1, time.Minute)
	b, _, _ := s.Issue(ctx, 1, time.Minute)
	if a == b {
		t.Error("two tokens issued for the same user in the same second are identical; revoking one would revoke both")
	}
}

func TestExpiryAndLeeway(t *testing.T) {
	now := time.Now()
	s := mustHS256(t)
	s.now = func() time.Time { return now }

	raw, _, _ := s.Issue(ctx, 7, time.Minute)

	s.now = func() time.Time { return now.Add(59 * time.Second) }
	if _, err := s.Validate(ctx, raw); err != nil {
		t.Errorf("token rejected before expiry: %v", err)
	}
	s.now = func() time.Time { return now.Add(61 * time.Second) }
	wantInvalid(t, s, raw, "expired token")

	tolerant := mustHS256(t, WithLeeway(30*time.Second))
	tolerant.now = s.now
	if _, err := tolerant.Validate(ctx, raw); err != nil {
		t.Errorf("token rejected inside the leeway: %v", err)
	}

	expired, _, _ := mustHS256(t).Issue(ctx, 7, -time.Minute)
	wantInvalid(t, mustHS256(t), expired, "token issued with a negative ttl")
}

func TestTamperingIsRejected(t *testing.T) {
	s := mustHS256(t)
	raw, _, _ := s.Issue(ctx, 1, time.Minute)
	parts := strings.Split(raw, ".")

	// Swap in a payload for another user while keeping the old signature.
	forgedClaims := `{"sub":"2","iat":1,"exp":9999999999,"jti":"x"}`
	wantInvalid(t, s, parts[0]+"."+b64.EncodeToString([]byte(forgedClaims))+"."+parts[2], "forged payload")

	wantInvalid(t, s, parts[0]+"."+parts[1]+"."+parts[2][:len(parts[2])-2]+"AA", "damaged signature")
	wantInvalid(t, s, parts[0]+"."+parts[1]+".", "empty signature")

	other, _ := NewHS256([]byte("a-completely-different-secret-xyz"))
	wantInvalid(t, other, raw, "token signed with another secret")
}

func TestAlgorithmAttacks(t *testing.T) {
	hs := mustHS256(t)
	validClaims := `{"sub":"1","iat":1,"exp":9999999999,"jti":"x"}`

	none := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64.EncodeToString([]byte(validClaims)) + "."
	wantInvalid(t, hs, none, "alg none without signature")
	wantInvalid(t, hs, forgeHS256(`{"alg":"none","typ":"JWT"}`, validClaims), "alg none with a signature")
	wantInvalid(t, hs, forgeHS256(`{"alg":"hs256","typ":"JWT"}`, validClaims), "alg in another case")
	wantInvalid(t, hs, forgeHS256(`{"typ":"JWT"}`, validClaims), "missing alg")

	// Classic confusion: an EdDSA verifier must not accept an HMAC token keyed with its public key.
	edSigner, pub := mustEdDSA(t)
	verifier, err := NewEdDSAVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, pub)
	input := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + b64.EncodeToString([]byte(validClaims))
	mac.Write([]byte(input))
	wantInvalid(t, verifier, input+"."+b64.EncodeToString(mac.Sum(nil)), "HS256 token against an EdDSA verifier")

	// And the other way around.
	edToken, _, _ := edSigner.Issue(ctx, 1, time.Minute)
	wantInvalid(t, hs, edToken, "EdDSA token against an HS256 strategy")
}

func TestMalformedInput(t *testing.T) {
	s := mustHS256(t)
	valid, _, _ := s.Issue(ctx, 1, time.Minute)
	for name, raw := range map[string]string{
		"empty":            "",
		"one part":         "abc",
		"two parts":        "a.b",
		"four parts":       valid + ".extra",
		"not base64":       "!!!.@@@.###",
		"header not json":  b64.EncodeToString([]byte("nope")) + ".e30.AAAA",
		"oversized":        strings.Repeat("a", maxTokenBytes+1),
		"padded base64url": strings.Replace(valid, ".", "=.", 1),
	} {
		wantInvalid(t, s, raw, name)
	}
}

func TestClaimRules(t *testing.T) {
	s := mustHS256(t)
	header := `{"alg":"HS256","typ":"JWT"}`
	wantInvalid(t, s, forgeHS256(header, `{"sub":"1","iat":1}`), "no exp claim")
	wantInvalid(t, s, forgeHS256(header, `{"sub":"abc","iat":1,"exp":9999999999}`), "non-numeric subject")
	wantInvalid(t, s, forgeHS256(header, `{"iat":1,"exp":9999999999}`), "no subject")
	wantInvalid(t, s, forgeHS256(header, `{"sub":"1","exp":"soon"}`), "exp of the wrong type")
	if _, err := s.Validate(ctx, forgeHS256(header, `{"sub":"1","iat":1,"exp":9999999999}`)); err != nil {
		t.Errorf("well-formed hand-made token rejected: %v", err)
	}
}

func TestIssuer(t *testing.T) {
	withIssuer := mustHS256(t, WithIssuer("auth.example.com"))
	raw, _, _ := withIssuer.Issue(ctx, 5, time.Minute)
	if got, err := withIssuer.Validate(ctx, raw); err != nil || got != 5 {
		t.Fatalf("Validate = %d, %v", got, err)
	}

	wantInvalid(t, mustHS256(t, WithIssuer("someone-else")), raw, "wrong issuer")
	noIssuer, _, _ := mustHS256(t).Issue(ctx, 5, time.Minute)
	wantInvalid(t, withIssuer, noIssuer, "missing issuer")
}

func TestVerifierCannotIssueButValidates(t *testing.T) {
	signer, pub := mustEdDSA(t)
	verifier, err := NewEdDSAVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}

	raw, _, err := signer.Issue(ctx, 9, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := verifier.Validate(ctx, raw); err != nil || got != 9 {
		t.Errorf("verifier rejected a valid token: %d, %v", got, err)
	}
	if _, _, err = verifier.Issue(ctx, 9, time.Minute); err == nil {
		t.Error("a verify-only strategy issued a token")
	}

	otherSigner, _ := mustEdDSA(t)
	foreign, _, _ := otherSigner.Issue(ctx, 9, time.Minute)
	wantInvalid(t, verifier, foreign, "token signed by another key")
}

func TestConstructorsRejectBadKeys(t *testing.T) {
	if _, err := NewHS256([]byte("too short")); err == nil {
		t.Error("short HS256 secret accepted")
	}
	if _, err := NewEdDSA(ed25519.PrivateKey("short")); err == nil {
		t.Error("short Ed25519 private key accepted")
	}
	if _, err := NewEdDSAVerifier(ed25519.PublicKey("short")); err == nil {
		t.Error("short Ed25519 public key accepted")
	}
}
