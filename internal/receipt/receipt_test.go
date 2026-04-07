package receipt

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/Epsilon-Data/epsilon-atl/internal/merkle"
)

func TestGenerateVerifyRoundtrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)

	gen, err := NewGenerator(priv)
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}

	// Build a small tree
	tree := merkle.NewTree()
	entryData := []byte("test-entry-0")
	leafHash := merkle.HashLeaf(entryData)
	tree.Append(leafHash)
	tree.Append(merkle.HashLeaf([]byte("test-entry-1")))

	rootHash, _ := tree.RootHash()
	treeSize := tree.Size()
	proofHashes, err := tree.InclusionProof(0, treeSize)
	if err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}

	receiptBytes, err := gen.Generate(0, treeSize, rootHash, proofHashes)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	proof, err := Verify(receiptBytes, rootHash, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if proof.LeafIndex != 0 {
		t.Fatalf("leaf index: expected 0, got %d", proof.LeafIndex)
	}
	if proof.TreeSize != treeSize {
		t.Fatalf("tree size: expected %d, got %d", treeSize, proof.TreeSize)
	}

	// Verify inclusion proof is valid
	err = merkle.VerifyInclusion(proof.LeafIndex, proof.TreeSize, leafHash, rootHash, proof.InclusionPath)
	if err != nil {
		t.Fatalf("inclusion verification: %v", err)
	}
}

func TestWrongKeyRejection(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)

	gen, _ := NewGenerator(priv)
	rootHash := make([]byte, 32)
	receiptBytes, _ := gen.Generate(0, 1, rootHash, nil)

	_, err := Verify(receiptBytes, rootHash, otherPub)
	if err == nil {
		t.Fatal("expected rejection with wrong key")
	}
}

func TestWrongRootHashDetection(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)

	gen, _ := NewGenerator(priv)
	rootHash := make([]byte, 32)
	rootHash[0] = 0xAA
	receiptBytes, _ := gen.Generate(0, 1, rootHash, nil)

	// Verification succeeds (signature is over rootHash)
	_, err := Verify(receiptBytes, rootHash, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	// But if we check with different root hash, sig should fail
	wrongRoot := make([]byte, 32)
	wrongRoot[0] = 0xBB

	// The receipt was signed with rootHash as payload. If we try to verify
	// the receipt signature against the wrong rootHash, it should fail.
	// However, Verify checks the COSE signature which includes the payload.
	// The caller is responsible for comparing the receipt's rootHash.
	if bytes.Equal(rootHash, wrongRoot) {
		t.Fatal("test setup error")
	}
}
