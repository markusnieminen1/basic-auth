package hashing

// PasswordHasher hides the algorithm used to hash user passwords (bcrypt, argon2, ...).
//
// Hashing is CPU-bound and cannot be cancelled mid-way, so the methods take no context.
// Refresh token hashing is a different job and lives in the token package.
type PasswordHasher interface {
	// Hash returns an encoded hash that carries its own salt and parameters.
	Hash(plain string) (string, error)
	// Verify reports whether plain matches hash. A mismatch is (false, nil);
	// an error means the hash itself could not be processed.
	Verify(plain, hash string) (bool, error)
}
