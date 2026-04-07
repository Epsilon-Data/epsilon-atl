package store

import (
	"database/sql"
	"fmt"
)

// AppendEntry inserts a new entry and returns its leaf index.
func (s *Store) AppendEntry(entryType int, entryCBOR, leafHash []byte, jobID, teePlatform, submitterID string) (int64, error) {
	var leafIndex int64
	err := s.db.QueryRow(`
		INSERT INTO atl_entries (entry_type, entry_cbor, leaf_hash, job_id, tee_platform, submitter_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING leaf_index`,
		entryType, entryCBOR, leafHash, jobID, teePlatform, submitterID,
	).Scan(&leafIndex)
	if err != nil {
		return 0, fmt.Errorf("inserting entry: %w", err)
	}
	// leaf_index is 1-based from BIGSERIAL; convert to 0-based
	return leafIndex - 1, nil
}

// GetEntry retrieves entry CBOR by 0-based index.
func (s *Store) GetEntry(index int64) ([]byte, error) {
	var entryCBOR []byte
	// Convert 0-based index to 1-based leaf_index
	err := s.db.QueryRow(`SELECT entry_cbor FROM atl_entries WHERE leaf_index = $1`, index+1).Scan(&entryCBOR)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("entry %d not found", index)
	}
	if err != nil {
		return nil, fmt.Errorf("querying entry: %w", err)
	}
	return entryCBOR, nil
}

// LeafHashExists checks if a leaf hash already exists (deduplication).
func (s *Store) LeafHashExists(leafHash []byte) (bool, error) {
	var exists bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM atl_entries WHERE leaf_hash = $1)`, leafHash).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("checking leaf hash: %w", err)
	}
	return exists, nil
}

// TreeSize returns the current number of entries.
func (s *Store) TreeSize() (uint64, error) {
	var count uint64
	err := s.db.QueryRow(`SELECT COALESCE(MAX(leaf_index), 0) FROM atl_entries`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting entries: %w", err)
	}
	return count, nil
}

// IterateLeafHashes calls fn for each leaf hash in insertion order.
// Used to rebuild the in-memory node cache on startup.
func (s *Store) IterateLeafHashes(fn func(index uint64, leafHash []byte) error) error {
	rows, err := s.db.Query(`SELECT leaf_index, leaf_hash FROM atl_entries ORDER BY leaf_index ASC`)
	if err != nil {
		return fmt.Errorf("querying leaf hashes: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dbIndex int64
		var leafHash []byte
		if err := rows.Scan(&dbIndex, &leafHash); err != nil {
			return fmt.Errorf("scanning leaf hash: %w", err)
		}
		// Convert 1-based DB index to 0-based
		if err := fn(uint64(dbIndex-1), leafHash); err != nil {
			return err
		}
	}
	return rows.Err()
}
