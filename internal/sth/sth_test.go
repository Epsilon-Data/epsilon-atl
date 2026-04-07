package sth

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(priv)
	rootHash := make([]byte, 32)
	rootHash[0] = 0xAB

	sth, err := signer.Sign(42, rootHash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if sth.TreeSize != 42 {
		t.Fatalf("expected tree size 42, got %d", sth.TreeSize)
	}
	if !Verify(sth, pub) {
		t.Fatal("verification failed for valid STH")
	}
}

func TestWrongKeyRejection(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)

	signer := NewSigner(priv)
	sth, _ := signer.Sign(1, make([]byte, 32))

	if Verify(sth, otherPub) {
		t.Fatal("verification should fail with wrong key")
	}
}

func TestTamperedFieldRejection(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer := NewSigner(priv)
	sth, _ := signer.Sign(10, make([]byte, 32))

	// Tamper tree size
	sth.TreeSize = 11
	if Verify(sth, pub) {
		t.Fatal("verification should fail with tampered tree size")
	}
}

func TestKeyPersistenceRoundtrip(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := GenerateKey()

	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")

	if err := SavePrivateKey(privPath, priv); err != nil {
		t.Fatalf("save private: %v", err)
	}
	if err := SavePublicKey(pubPath, pub); err != nil {
		t.Fatalf("save public: %v", err)
	}

	// Check permissions
	info, _ := os.Stat(privPath)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %o", info.Mode().Perm())
	}

	loadedPriv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("load private: %v", err)
	}
	loadedPub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load public: %v", err)
	}

	// Sign with loaded key, verify with loaded pub
	signer := NewSigner(loadedPriv)
	sth, _ := signer.Sign(1, make([]byte, 32))
	if !Verify(sth, loadedPub) {
		t.Fatal("roundtrip key verification failed")
	}
}
