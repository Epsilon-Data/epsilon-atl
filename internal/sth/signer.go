package sth

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

// Signer creates signed tree heads.
type Signer struct {
	key ed25519.PrivateKey
}

// NewSigner creates a new STH signer.
func NewSigner(key ed25519.PrivateKey) *Signer {
	return &Signer{key: key}
}

// Sign creates a signed tree head for the given tree state.
func (s *Signer) Sign(treeSize uint64, rootHash []byte) (*SignedTreeHead, error) {
	payload := TreeHeadPayload{
		TreeSize:  treeSize,
		RootHash:  rootHash,
		Timestamp: time.Now().Unix(),
	}
	payloadBytes, err := entry.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling tree head payload: %w", err)
	}
	sig := ed25519.Sign(s.key, payloadBytes)
	return &SignedTreeHead{
		TreeSize:  payload.TreeSize,
		RootHash:  payload.RootHash,
		Timestamp: payload.Timestamp,
		Signature: sig,
	}, nil
}
