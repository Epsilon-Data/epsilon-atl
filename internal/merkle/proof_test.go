package merkle

import (
	"testing"
)

func TestInclusionProof(t *testing.T) {
	tree := NewTree()
	n := 8
	leafHashes := make([][]byte, n)
	for i := 0; i < n; i++ {
		leafHashes[i] = HashLeaf([]byte{byte(i)})
		tree.Append(leafHashes[i])
	}

	root, _ := tree.RootHash()
	treeSize := tree.Size()

	for i := uint64(0); i < treeSize; i++ {
		proofHashes, err := tree.InclusionProof(i, treeSize)
		if err != nil {
			t.Fatalf("inclusion proof for index %d: %v", i, err)
		}
		if err := VerifyInclusion(i, treeSize, leafHashes[i], root, proofHashes); err != nil {
			t.Fatalf("verify inclusion for index %d: %v", i, err)
		}
	}
}

func TestInclusionProofNonPowerOfTwo(t *testing.T) {
	tree := NewTree()
	n := 5
	leafHashes := make([][]byte, n)
	for i := 0; i < n; i++ {
		leafHashes[i] = HashLeaf([]byte{byte(i)})
		tree.Append(leafHashes[i])
	}

	root, _ := tree.RootHash()
	treeSize := tree.Size()

	for i := uint64(0); i < treeSize; i++ {
		proofHashes, err := tree.InclusionProof(i, treeSize)
		if err != nil {
			t.Fatalf("inclusion proof for index %d: %v", i, err)
		}
		if err := VerifyInclusion(i, treeSize, leafHashes[i], root, proofHashes); err != nil {
			t.Fatalf("verify inclusion for index %d: %v", i, err)
		}
	}
}

func TestConsistencyProof(t *testing.T) {
	tree := NewTree()
	leafHashes := make([][]byte, 0)
	roots := make([][]byte, 0)

	for i := 0; i < 8; i++ {
		h := HashLeaf([]byte{byte(i)})
		leafHashes = append(leafHashes, h)
		tree.Append(h)
		root, _ := tree.RootHash()
		roots = append(roots, root)
	}

	// Test consistency between various sizes
	testCases := [][2]uint64{
		{1, 2}, {1, 4}, {1, 8},
		{2, 4}, {2, 8},
		{4, 8},
		{3, 7}, {5, 8},
	}

	for _, tc := range testCases {
		first, second := tc[0], tc[1]
		proofHashes, err := tree.ConsistencyProof(first, second)
		if err != nil {
			t.Fatalf("consistency proof %d->%d: %v", first, second, err)
		}
		if err := VerifyConsistency(first, second, roots[first-1], roots[second-1], proofHashes); err != nil {
			t.Fatalf("verify consistency %d->%d: %v", first, second, err)
		}
	}
}

func TestInclusionProofBoundaryErrors(t *testing.T) {
	tree := NewTree()
	tree.Append(HashLeaf([]byte{0}))

	// Index >= tree size
	_, err := tree.InclusionProof(1, 1)
	if err == nil {
		t.Fatal("expected error for index >= tree size")
	}

	// Tree size > current size
	_, err = tree.InclusionProof(0, 10)
	if err == nil {
		t.Fatal("expected error for tree size > current")
	}
}

func TestConsistencyProofBoundaryErrors(t *testing.T) {
	tree := NewTree()
	tree.Append(HashLeaf([]byte{0}))
	tree.Append(HashLeaf([]byte{1}))

	// first > second
	_, err := tree.ConsistencyProof(2, 1)
	if err == nil {
		t.Fatal("expected error for first > second")
	}

	// second > current size
	_, err = tree.ConsistencyProof(1, 10)
	if err == nil {
		t.Fatal("expected error for second > current size")
	}
}

func TestTamperedProofRejection(t *testing.T) {
	tree := NewTree()
	for i := 0; i < 4; i++ {
		tree.Append(HashLeaf([]byte{byte(i)}))
	}

	root, _ := tree.RootHash()
	leafHash := HashLeaf([]byte{0})
	proofHashes, _ := tree.InclusionProof(0, 4)

	// Tamper with proof
	tampered := make([][]byte, len(proofHashes))
	copy(tampered, proofHashes)
	if len(tampered) > 0 {
		tampered[0] = make([]byte, 32) // zero hash
	}

	err := VerifyInclusion(0, 4, leafHash, root, tampered)
	if err == nil {
		t.Fatal("expected verification failure for tampered proof")
	}
}
