package sth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateKey creates a new Ed25519 keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// SavePrivateKey writes an Ed25519 private key in PKCS8 PEM format.
func SavePrivateKey(path string, key ed25519.PrivateKey) error {
	bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bytes})
	return os.WriteFile(path, data, 0600)
}

// LoadPrivateKey reads an Ed25519 private key from PKCS8 PEM format.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return ed, nil
}

// SavePublicKey writes an Ed25519 public key in PKIX PEM format.
func SavePublicKey(path string, key ed25519.PublicKey) error {
	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bytes})
	return os.WriteFile(path, data, 0644)
}

// LoadPublicKey reads an Ed25519 public key from PKIX PEM format.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return ed, nil
}
