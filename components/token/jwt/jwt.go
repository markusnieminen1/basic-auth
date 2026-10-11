// Package jwt is a token.AccessStrategy that issues and validates JWTs using only the
// standard library.
//
// Two algorithms are supported:
//   - HS256 (HMAC-SHA256, shared secret): NewHS256. Every service that validates
//     tokens needs the secret, and therefore could also forge them.
//   - EdDSA (Ed25519, key pair): NewEdDSA signs and validates, NewEdDSAVerifier only
//     validates. Services that just check tokens need the public key only.
//
// A Strategy accepts only the algorithm it was built with. The "alg" header of an
// incoming token is checked against it, never trusted, which rules out "alg: none" and
// algorithm-confusion attacks.
package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/markusnieminen1/basic-auth/components/token"
)

const (
	minHMACSecretBytes = 32
	maxTokenBytes      = 4096
)

var (
	errVerifyOnly = errors.New("jwt: strategy has no private key and cannot issue tokens")
	b64           = base64.RawURLEncoding
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type claims struct {
	Subject   string `json:"sub"`
	Issuer    string `json:"iss,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	ID        string `json:"jti"`
}

// algorithm is one JWT signature scheme. sign is nil for a verify-only strategy.
type algorithm struct {
	name   string
	sign   func(message []byte) []byte
	verify func(message, signature []byte) bool
}

type Strategy struct {
	alg    algorithm
	issuer string
	leeway time.Duration
	now    func() time.Time
}

type Option func(*Strategy)

// WithIssuer sets the "iss" claim on issued tokens and requires it on validated ones.
func WithIssuer(issuer string) Option {
	return func(s *Strategy) { s.issuer = issuer }
}

// WithLeeway tolerates clock differences between services when checking expiry.
func WithLeeway(leeway time.Duration) Option {
	return func(s *Strategy) { s.leeway = leeway }
}

// NewHS256 returns a strategy signing with HMAC-SHA256. The secret must be at least 32 bytes.
func NewHS256(secret []byte, opts ...Option) (*Strategy, error) {
	if len(secret) < minHMACSecretBytes {
		return nil, fmt.Errorf("jwt: HS256 secret must be at least %d bytes, got %d", minHMACSecretBytes, len(secret))
	}
	key := append([]byte(nil), secret...)
	mac := func(message []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(message)
		return h.Sum(nil)
	}
	return newStrategy(algorithm{
		name:   "HS256",
		sign:   mac,
		verify: func(message, signature []byte) bool { return hmac.Equal(mac(message), signature) },
	}, opts), nil
}

// NewEdDSA returns a strategy that signs with the private key and validates with its public key.
func NewEdDSA(key ed25519.PrivateKey, opts ...Option) (*Strategy, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("jwt: invalid Ed25519 private key size %d", len(key))
	}
	pub := key.Public().(ed25519.PublicKey)
	return newStrategy(algorithm{
		name:   "EdDSA",
		sign:   func(message []byte) []byte { return ed25519.Sign(key, message) },
		verify: func(message, signature []byte) bool { return ed25519.Verify(pub, message, signature) },
	}, opts), nil
}

// NewEdDSAVerifier returns a strategy that only validates tokens. Issue always fails.
func NewEdDSAVerifier(pub ed25519.PublicKey, opts ...Option) (*Strategy, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jwt: invalid Ed25519 public key size %d", len(pub))
	}
	return newStrategy(algorithm{
		name:   "EdDSA",
		verify: func(message, signature []byte) bool { return ed25519.Verify(pub, message, signature) },
	}, opts), nil
}

func newStrategy(alg algorithm, opts []Option) *Strategy {
	s := &Strategy{alg: alg, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Issue creates a signed token for the user. The returned expiry is the exact "exp"
// claim (whole seconds), so the cookie and the token cannot disagree.
func (s *Strategy) Issue(ctx context.Context, userID int64, ttl time.Duration) (string, time.Time, error) {
	if s.alg.sign == nil {
		return "", time.Time{}, errVerifyOnly
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}

	issuedAt := s.now()
	expiresAt := time.Unix(issuedAt.Add(ttl).Unix(), 0)

	headerJSON, err := json.Marshal(header{Alg: s.alg.name, Typ: "JWT"})
	if err != nil {
		return "", time.Time{}, err
	}
	claimsJSON, err := json.Marshal(claims{
		Subject:   strconv.FormatInt(userID, 10),
		Issuer:    s.issuer,
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: expiresAt.Unix(),
		ID:        hex.EncodeToString(jti),
	})
	if err != nil {
		return "", time.Time{}, err
	}

	signingInput := b64.EncodeToString(headerJSON) + "." + b64.EncodeToString(claimsJSON)
	signature := s.alg.sign([]byte(signingInput))
	return signingInput + "." + b64.EncodeToString(signature), expiresAt, nil
}

// Validate checks signature, algorithm, expiry and issuer and returns the user ID.
// Every failure wraps token.ErrInvalidToken.
func (s *Strategy) Validate(ctx context.Context, rawToken string) (int64, error) {
	if len(rawToken) > maxTokenBytes {
		return 0, invalid("token too large")
	}
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return 0, invalid("malformed token")
	}

	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return 0, invalid("malformed header")
	}
	if h.Alg != s.alg.name {
		return 0, invalid("unexpected algorithm")
	}

	signature, err := b64.DecodeString(parts[2])
	if err != nil {
		return 0, invalid("malformed signature")
	}
	if !s.alg.verify([]byte(parts[0]+"."+parts[1]), signature) {
		return 0, invalid("bad signature")
	}

	// Only now is the payload authentic and worth parsing.
	var c claims
	if err = decodeSegment(parts[1], &c); err != nil {
		return 0, invalid("malformed claims")
	}
	if c.ExpiresAt == 0 {
		return 0, invalid("missing expiry")
	}
	if !s.now().Before(time.Unix(c.ExpiresAt, 0).Add(s.leeway)) {
		return 0, invalid("expired")
	}
	if s.issuer != "" && c.Issuer != s.issuer {
		return 0, invalid("unexpected issuer")
	}
	userID, err := strconv.ParseInt(c.Subject, 10, 64)
	if err != nil {
		return 0, invalid("bad subject")
	}
	return userID, nil
}

func decodeSegment(segment string, into any) error {
	raw, err := b64.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", token.ErrInvalidToken, reason)
}

var _ token.AccessStrategy = (*Strategy)(nil)
