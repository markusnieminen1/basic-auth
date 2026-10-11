package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestKeyIsCreatedOnceAndReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")

	first, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Error("the key changed between loads, a restart would sign everybody out")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %v, want 0600", perm)
	}

	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".jwt-key-*"))
	if len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
}

func TestDefaultPathIsTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if _, err := LoadOrCreateKey(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, DefaultKeyFile)); err != nil {
		t.Errorf("default key file not created in the working directory: %v", err)
	}
}

func TestTokensSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")

	before, err := NewEdDSAFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := before.Issue(ctx, 11, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	after, err := NewEdDSAFromFile(path) // a new process loading the same file
	if err != nil {
		t.Fatal(err)
	}
	if got, err := after.Validate(ctx, raw); err != nil || got != 11 {
		t.Errorf("token from before the restart: %d, %v", got, err)
	}
}

func TestConcurrentStartupsAgreeOnOneKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	const n = 8

	keys := make([][]byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := LoadOrCreateKey(path)
			if err != nil {
				t.Error(err)
				return
			}
			keys[i] = key
		}()
	}
	wg.Wait()

	for i := 1; i < n; i++ {
		if string(keys[i]) != string(keys[0]) {
			t.Fatalf("process %d ended up with a different key", i)
		}
	}
}

func TestUnusableKeyFilesAreRefusedNotOverwritten(t *testing.T) {
	dir := t.TempDir()

	garbage := filepath.Join(dir, "garbage.pem")
	os.WriteFile(garbage, []byte("not a key"), 0o600)

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	wrongType := filepath.Join(dir, "ec.pem")
	os.WriteFile(wrongType, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)

	for name, path := range map[string]string{"garbage": garbage, "ECDSA key": wrongType} {
		before, _ := os.ReadFile(path)
		if _, err := LoadOrCreateKey(path); err == nil {
			t.Errorf("%s accepted", name)
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Errorf("%s: the existing file was overwritten", name)
		}
	}
}
