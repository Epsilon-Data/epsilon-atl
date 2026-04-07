package merkle

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestEmptyTree(t *testing.T) {
	tree := NewTree()
	if tree.Size() != 0 {
		t.Fatalf("expected size 0, got %d", tree.Size())
	}
	root, err := tree.RootHash()
	if err != nil {
		t.Fatalf("root hash error: %v", err)
	}
	if root != nil {
		t.Fatalf("expected nil root for empty tree, got %x", root)
	}
}

func TestSingleLeaf(t *testing.T) {
	tree := NewTree()
	leaf := []byte("entry-0")
	leafHash := HashLeaf(leaf)
	if err := tree.Append(leafHash); err != nil {
		t.Fatalf("append: %v", err)
	}
	if tree.Size() != 1 {
		t.Fatalf("expected size 1, got %d", tree.Size())
	}
	root, err := tree.RootHash()
	if err != nil {
		t.Fatalf("root hash: %v", err)
	}
	// For a single leaf, root = leaf hash
	if !bytes.Equal(root, leafHash) {
		t.Fatalf("single leaf root mismatch: %x != %x", root, leafHash)
	}
}

func TestTwoLeaves(t *testing.T) {
	tree := NewTree()
	h0 := HashLeaf([]byte("entry-0"))
	h1 := HashLeaf([]byte("entry-1"))
	tree.Append(h0)
	tree.Append(h1)

	root, _ := tree.RootHash()
	expected := HashChildren(h0, h1)
	if !bytes.Equal(root, expected) {
		t.Fatalf("two-leaf root mismatch: %x != %x", root, expected)
	}
}

func TestRFC6962LeafHash(t *testing.T) {
	// RFC 6962 / 9162: H(0x00 || data)
	data := []byte("test")
	got := HashLeaf(data)

	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	expected := h.Sum(nil)

	if !bytes.Equal(got, expected) {
		t.Fatalf("leaf hash mismatch: %x != %x", got, expected)
	}
}

func TestRFC6962InteriorHash(t *testing.T) {
	// RFC 6962 / 9162: H(0x01 || left || right)
	left := []byte("left-hash-placeholder-32-bytes!!")
	right := []byte("right-hash-placeholder-32bytes!!")
	got := HashChildren(left, right)

	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	expected := h.Sum(nil)

	if !bytes.Equal(got, expected) {
		t.Fatalf("interior hash mismatch: %x != %x", got, expected)
	}
}

func TestPowerOfTwoTree(t *testing.T) {
	tree := NewTree()
	hashes := make([][]byte, 4)
	for i := range hashes {
		hashes[i] = HashLeaf([]byte{byte(i)})
		tree.Append(hashes[i])
	}

	root, _ := tree.RootHash()
	// Manual computation: H(H(h0,h1), H(h2,h3))
	left := HashChildren(hashes[0], hashes[1])
	right := HashChildren(hashes[2], hashes[3])
	expected := HashChildren(left, right)

	if !bytes.Equal(root, expected) {
		t.Fatalf("4-leaf root mismatch: %x != %x", root, expected)
	}
}

func TestNonPowerOfTwoTree(t *testing.T) {
	tree := NewTree()
	hashes := make([][]byte, 3)
	for i := range hashes {
		hashes[i] = HashLeaf([]byte{byte(i)})
		tree.Append(hashes[i])
	}

	root, _ := tree.RootHash()
	if root == nil {
		t.Fatal("expected non-nil root for 3-leaf tree")
	}
	if len(root) != 32 {
		t.Fatalf("expected 32-byte root, got %d", len(root))
	}
}

func TestCompactStateRoundtrip(t *testing.T) {
	tree := NewTree()
	for i := 0; i < 7; i++ {
		h := HashLeaf([]byte{byte(i)})
		tree.Append(h)
	}
	origRoot, _ := tree.RootHash()
	size, hashes := tree.CompactState()
	nodes := tree.InternalNodes()

	restored := NewTree()
	if err := restored.RestoreFromState(size, hashes, nodes); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restoredRoot, _ := restored.RootHash()
	if !bytes.Equal(origRoot, restoredRoot) {
		t.Fatalf("root mismatch after restore: %x != %x", origRoot, restoredRoot)
	}
	if restored.Size() != tree.Size() {
		t.Fatalf("size mismatch: %d != %d", restored.Size(), tree.Size())
	}

	// Append to restored tree and verify it still works
	h := HashLeaf([]byte{7})
	if err := restored.Append(h); err != nil {
		t.Fatalf("append after restore: %v", err)
	}
	if restored.Size() != 8 {
		t.Fatalf("expected size 8, got %d", restored.Size())
	}
}
