package store

import (
	"database/sql"
	"fmt"

	"github.com/Epsilon-Data/epsilon-atl/internal/sth"
)

// SaveSTH persists a signed tree head.
func (s *Store) SaveSTH(h *sth.SignedTreeHead) error {
	_, err := s.db.Exec(`
		INSERT INTO tree_heads (tree_size, root_hash, timestamp, signature)
		VALUES ($1, $2, $3, $4)`,
		h.TreeSize, h.RootHash, h.Timestamp, h.Signature,
	)
	if err != nil {
		return fmt.Errorf("saving STH: %w", err)
	}
	return nil
}

// LatestSTH retrieves the most recent signed tree head.
func (s *Store) LatestSTH() (*sth.SignedTreeHead, error) {
	h := &sth.SignedTreeHead{}
	err := s.db.QueryRow(`
		SELECT tree_size, root_hash, timestamp, signature
		FROM tree_heads ORDER BY id DESC LIMIT 1`,
	).Scan(&h.TreeSize, &h.RootHash, &h.Timestamp, &h.Signature)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying latest STH: %w", err)
	}
	return h, nil
}

// GetSTHBySize retrieves the STH for a specific tree size.
func (s *Store) GetSTHBySize(treeSize uint64) (*sth.SignedTreeHead, error) {
	h := &sth.SignedTreeHead{}
	err := s.db.QueryRow(`
		SELECT tree_size, root_hash, timestamp, signature
		FROM tree_heads WHERE tree_size = $1
		ORDER BY id DESC LIMIT 1`, treeSize,
	).Scan(&h.TreeSize, &h.RootHash, &h.Timestamp, &h.Signature)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying STH by size: %w", err)
	}
	return h, nil
}
