// Package jwt satisfies token.AccessTokenLogic. It issues and validates Ed25519 (EdDSA) signed JWTs
// with github.com/golang-jwt/jwt/v5. Ed25519 is the only algorithm accepted, so "alg: none" is refused.
package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/markusnieminen1/basic-auth/components/token"
)

type Access struct {
	key ed25519.PrivateKey
}

// NewEdDSALogic returns a Access that signs with the private key and validates with its public key.
func NewEdDSALogic(key ed25519.PrivateKey) (*Access, error) {

	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("jwt: invalid Ed25519 private key size %d", len(key))
	}

	return &Access{key: key}, nil
}

// Issue creates signed token for the user
func (s *Access) Issue(ctx context.Context, userID int64, ttl time.Duration) (string, time.Time, error) {

	jti := make([]byte, 16)

	// Fill with random bytes
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}

	issuedAt := time.Now()
	expiresAt := time.Unix(issuedAt.Add(ttl).Unix(), 0)

	signed, err := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, gojwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		IssuedAt:  gojwt.NewNumericDate(issuedAt),
		ExpiresAt: gojwt.NewNumericDate(expiresAt),
		ID:        hex.EncodeToString(jti),
	}).SignedString(s.key)

	if err != nil {
		return "", time.Time{}, err
	}

	return signed, expiresAt, nil
}

// Validate checks signature, algorithm and expiry and returns the user ID
func (s *Access) Validate(ctx context.Context, rawToken string) (int64, error) {
	parser := gojwt.NewParser(gojwt.WithValidMethods([]string{gojwt.SigningMethodEdDSA.Alg()}), gojwt.WithExpirationRequired())

	var claims gojwt.RegisteredClaims
	_, err := parser.ParseWithClaims(rawToken, &claims, func(*gojwt.Token) (any, error) {
		return s.key.Public(), nil
	})
	if err != nil {
		return 0, fmt.Errorf("%w: %v", token.ErrInvalidToken, err)
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: bad subject", token.ErrInvalidToken)
	}
	return userID, nil
}

var _ token.AccessTokenLogic = (*Access)(nil)
