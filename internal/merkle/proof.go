package merkle

import (
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
)

// InclusionProof generates an inclusion proof for the leaf at index in a tree of treeSize.
func (t *Tree) InclusionProof(index, treeSize uint64) ([][]byte, error) {
	if index >= treeSize {
		return nil, fmt.Errorf("index %d >= tree size %d", index, treeSize)
	}
	if treeSize > t.Size() {
		return nil, fmt.Errorf("requested tree size %d > current size %d", treeSize, t.Size())
	}

	nodes, err := proof.Inclusion(index, treeSize)
	if err != nil {
		return nil, fmt.Errorf("computing inclusion proof nodes: %w", err)
	}
	return t.fetchAndRehash(nodes)
}

// ConsistencyProof generates a consistency proof between two tree sizes.
func (t *Tree) ConsistencyProof(first, second uint64) ([][]byte, error) {
	if first > second {
		return nil, fmt.Errorf("first %d > second %d", first, second)
	}
	if second > t.Size() {
		return nil, fmt.Errorf("requested tree size %d > current size %d", second, t.Size())
	}
	if first == 0 {
		return [][]byte{}, nil
	}

	nodes, err := proof.Consistency(first, second)
	if err != nil {
		return nil, fmt.Errorf("computing consistency proof nodes: %w", err)
	}
	return t.fetchAndRehash(nodes)
}

// fetchAndRehash fetches node hashes and applies Rehash to handle ephemeral nodes.
func (t *Tree) fetchAndRehash(nodes proof.Nodes) ([][]byte, error) {
	hashes := make([][]byte, len(nodes.IDs))
	fetcher := t.NodeFetcher()
	for i, id := range nodes.IDs {
		h, err := fetcher(id)
		if err != nil {
			h, err = t.computeNode(id)
			if err != nil {
				return nil, fmt.Errorf("fetching node %v: %w", id, err)
			}
		}
		hashes[i] = h
	}
	return nodes.Rehash(hashes, HashChildren)
}

func (t *Tree) computeNode(id compact.NodeID) ([]byte, error) {
	if id.Level == 0 {
		return nil, fmt.Errorf("leaf node %v not in cache", id)
	}
	left := compact.NewNodeID(id.Level-1, id.Index*2)
	right := compact.NewNodeID(id.Level-1, id.Index*2+1)

	fetcher := t.NodeFetcher()
	lh, err := fetcher(left)
	if err != nil {
		lh, err = t.computeNode(left)
		if err != nil {
			return nil, err
		}
	}
	rh, err := fetcher(right)
	if err != nil {
		rh, err = t.computeNode(right)
		if err != nil {
			return nil, err
		}
	}
	h := HashChildren(lh, rh)
	t.mu.Lock()
	t.nodes[id] = h
	t.mu.Unlock()
	return h, nil
}

// VerifyInclusion verifies an inclusion proof.
func VerifyInclusion(index, treeSize uint64, leafHash, rootHash []byte, proofHashes [][]byte) error {
	return proof.VerifyInclusion(hasher, index, treeSize, leafHash, proofHashes, rootHash)
}

// VerifyConsistency verifies a consistency proof.
func VerifyConsistency(first, second uint64, rootFirst, rootSecond []byte, proofHashes [][]byte) error {
	return proof.VerifyConsistency(hasher, first, second, proofHashes, rootFirst, rootSecond)
}
