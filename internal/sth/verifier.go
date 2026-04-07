package sth

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

// Verify checks the Ed25519 signature on a signed tree head.
func Verify(s *SignedTreeHead, publicKey ed25519.PublicKey) bool {
	payload := TreeHeadPayload{
		TreeSize:  s.TreeSize,
		RootHash:  s.RootHash,
		Timestamp: s.Timestamp,
	}
	payloadBytes, err := entry.Marshal(payload)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, payloadBytes, s.Signature)
}

// VerifyOrError is like Verify but returns a descriptive error.
func VerifyOrError(s *SignedTreeHead, publicKey ed25519.PublicKey) error {
	if !Verify(s, publicKey) {
		return fmt.Errorf("STH signature verification failed")
	}
	return nil
}
