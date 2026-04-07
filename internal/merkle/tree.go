package merkle

import (
	"fmt"
	"sync"

	"github.com/transparency-dev/merkle/compact"
)

// Tree wraps a compact.Range for incremental Merkle tree construction.
type Tree struct {
	mu      sync.Mutex
	factory *compact.RangeFactory
	cr      *compact.Range
	nodes   map[compact.NodeID][]byte
}

// NewTree creates an empty tree.
func NewTree() *Tree {
	t := &Tree{
		nodes: make(map[compact.NodeID][]byte),
	}
	t.factory = &compact.RangeFactory{
		Hash: func(left, right []byte) []byte {
			h := HashChildren(left, right)
			return h
		},
	}
	t.cr = t.factory.NewEmptyRange(0)
	return t
}

// Append adds a leaf hash to the tree and stores any interior nodes produced.
func (t *Tree) Append(leafHash []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	idx := t.cr.End()
	// Store the leaf node
	t.nodes[compact.NewNodeID(0, idx)] = leafHash

	visitor := func(id compact.NodeID, hash []byte) {
		t.nodes[id] = hash
	}
	if err := t.cr.Append(leafHash, visitor); err != nil {
		return fmt.Errorf("append to compact range: %w", err)
	}
	return nil
}

// RootHash returns the current root hash, or nil for an empty tree.
func (t *Tree) RootHash() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cr.End() == 0 {
		return nil, nil
	}

	visitor := func(id compact.NodeID, hash []byte) {
		t.nodes[id] = hash
	}
	root, err := t.cr.GetRootHash(visitor)
	if err != nil {
		return nil, fmt.Errorf("computing root hash: %w", err)
	}
	return root, nil
}

// Size returns the number of leaves in the tree.
func (t *Tree) Size() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cr.End()
}

// CompactState returns the compact range state for persistence.
func (t *Tree) CompactState() (uint64, [][]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cr.End(), t.cr.Hashes()
}

// InternalNodes returns a copy of the internal node cache.
func (t *Tree) InternalNodes() map[compact.NodeID][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make(map[compact.NodeID][]byte, len(t.nodes))
	for k, v := range t.nodes {
		cp[k] = v
	}
	return cp
}

// RestoreFromState reconstructs the tree from persisted compact range state and node cache.
func (t *Tree) RestoreFromState(size uint64, hashes [][]byte, nodes map[compact.NodeID][]byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	cr, err := t.factory.NewRange(0, size, hashes)
	if err != nil {
		return fmt.Errorf("restoring compact range: %w", err)
	}
	t.cr = cr
	t.nodes = nodes
	return nil
}

// RebuildNodeCache reconstructs the internal node cache by re-appending all leaf hashes.
// Call this after RestoreFromState to populate the node cache for proof generation
// without needing to persist the full node map.
func (t *Tree) RebuildNodeCache(leafHashes func(fn func(index uint64, leafHash []byte) error) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Reset to empty tree
	t.nodes = make(map[compact.NodeID][]byte)
	t.cr = t.factory.NewEmptyRange(0)

	var count uint64
	err := leafHashes(func(index uint64, leafHash []byte) error {
		// Store leaf node
		t.nodes[compact.NewNodeID(0, index)] = leafHash
		// Append to compact range, capturing interior nodes
		visitor := func(id compact.NodeID, hash []byte) {
			t.nodes[id] = hash
		}
		if err := t.cr.Append(leafHash, visitor); err != nil {
			return fmt.Errorf("appending leaf %d: %w", index, err)
		}
		count++
		if count%100000 == 0 {
			fmt.Printf("  Rebuilt %d nodes...\n", count)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("rebuilding node cache: %w", err)
	}
	return nil
}

// NodeFetcher returns a function suitable for proof generation that reads from the node cache.
func (t *Tree) NodeFetcher() func(id compact.NodeID) ([]byte, error) {
	return func(id compact.NodeID) ([]byte, error) {
		t.mu.Lock()
		defer t.mu.Unlock()
		h, ok := t.nodes[id]
		if !ok {
			return nil, fmt.Errorf("node %v not found in cache", id)
		}
		return h, nil
	}
}
