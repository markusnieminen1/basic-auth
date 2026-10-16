package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultKeyFile is the file, in the working directory, used when no path is given.
const DefaultKeyFile = "jwt_ed25519.pem"

// LoadOrCreateKey returns the Ed25519 private key stored at path (PEM, PKCS#8).
// If the file does not exist, a new key is generated and saved there with mode 0600.
// An empty path means DefaultKeyFile in the working directory.
//
// The key file must be kept out of version control and shared by every instance that
// issues tokens, since a key that changes on restart signs everybody out. Generating
// the key is safe to race: if several processes start at once, one file wins and all of
// them end up using it.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		path = DefaultKeyFile
	}

	key, err := readKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	_, key, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err = writeKeyExclusively(path, key); errors.Is(err, os.ErrExist) {
		return readKey(path) // another process created it first
	} else if err != nil {
		return nil, err
	}
	return key, nil
}

// NewEdDSAFromFile builds an EdDSA Access from LoadOrCreateKey(path).
func NewEdDSAFromFile(path string) (*Access, error) {
	key, err := LoadOrCreateKey(path)
	if err != nil {
		return nil, err
	}
	return NewEdDSALogic(key)
}

func readKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("jwt: %s is not a PEM encoded private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwt: %s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("jwt: %s holds a %T key, an Ed25519 key is required", path, parsed)
	}
	return key, nil
}

// writeKeyExclusively saves the key so that readers never see a half written file:
// it is written to a private temporary file first and then hard-linked into place,
// which fails with os.ErrExist if the target already exists.
func writeKeyExclusively(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	tmp, err := os.CreateTemp(filepath.Dir(path), ".jwt-key-*") // created with mode 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err = tmp.Write(encoded); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Link(tmp.Name(), path)
}
