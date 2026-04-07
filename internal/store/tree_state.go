package store

import (
	"database/sql"
	"encoding/binary"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
)

// SaveTreeState persists the compact range state.
// Internal nodes are NOT persisted — they are rebuilt from leaf hashes on startup.
// This keeps the tree_state row small: O(log n) hashes instead of O(n) nodes.
func (s *Store) SaveTreeState(size uint64, hashes [][]byte, nodes map[compact.NodeID][]byte) error {
	compactBytes := encodeHashes(hashes)
	// Store empty node map — nodes are rebuilt on startup from leaf hashes
	emptyNodes := encodeNodeMap(map[compact.NodeID][]byte{})

	_, err := s.db.Exec(`
		INSERT INTO tree_state (id, tree_size, compact_hashes, internal_nodes)
		VALUES (1, $1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET
			tree_size = $1, compact_hashes = $2, internal_nodes = $3, updated_at = NOW()`,
		size, compactBytes, emptyNodes,
	)
	if err != nil {
		return fmt.Errorf("saving tree state: %w", err)
	}
	return nil
}

// LoadTreeState loads the persisted compact range state and node cache.
func (s *Store) LoadTreeState() (uint64, [][]byte, map[compact.NodeID][]byte, error) {
	var size uint64
	var compactBytes, nodeBytes []byte
	err := s.db.QueryRow(`SELECT tree_size, compact_hashes, internal_nodes FROM tree_state WHERE id = 1`).
		Scan(&size, &compactBytes, &nodeBytes)
	if err == sql.ErrNoRows {
		return 0, nil, nil, nil
	}
	if err != nil {
		return 0, nil, nil, fmt.Errorf("loading tree state: %w", err)
	}
	hashes := decodeHashes(compactBytes)
	nodes := decodeNodeMap(nodeBytes)
	return size, hashes, nodes, nil
}

// encodeHashes serializes a slice of hash byte slices.
// Format: [count:4][len:4][bytes]...
func encodeHashes(hashes [][]byte) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(hashes)))
	for _, h := range hashes {
		lb := make([]byte, 4)
		binary.BigEndian.PutUint32(lb, uint32(len(h)))
		buf = append(buf, lb...)
		buf = append(buf, h...)
	}
	return buf
}

func decodeHashes(data []byte) [][]byte {
	if len(data) < 4 {
		return nil
	}
	count := binary.BigEndian.Uint32(data[:4])
	pos := 4
	hashes := make([][]byte, 0, count)
	for i := uint32(0); i < count; i++ {
		if pos+4 > len(data) {
			break
		}
		ln := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		if pos+int(ln) > len(data) {
			break
		}
		h := make([]byte, ln)
		copy(h, data[pos:pos+int(ln)])
		pos += int(ln)
		hashes = append(hashes, h)
	}
	return hashes
}

// encodeNodeMap serializes the node cache.
// Format: [count:4][level:4][index:8][len:4][bytes]...
func encodeNodeMap(nodes map[compact.NodeID][]byte) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(nodes)))
	for id, h := range nodes {
		entry := make([]byte, 16)
		binary.BigEndian.PutUint32(entry[0:4], uint32(id.Level))
		binary.BigEndian.PutUint64(entry[4:12], id.Index)
		binary.BigEndian.PutUint32(entry[12:16], uint32(len(h)))
		buf = append(buf, entry...)
		buf = append(buf, h...)
	}
	return buf
}

func decodeNodeMap(data []byte) map[compact.NodeID][]byte {
	if len(data) < 4 {
		return make(map[compact.NodeID][]byte)
	}
	count := binary.BigEndian.Uint32(data[:4])
	pos := 4
	nodes := make(map[compact.NodeID][]byte, count)
	for i := uint32(0); i < count; i++ {
		if pos+16 > len(data) {
			break
		}
		level := binary.BigEndian.Uint32(data[pos : pos+4])
		index := binary.BigEndian.Uint64(data[pos+4 : pos+12])
		ln := binary.BigEndian.Uint32(data[pos+12 : pos+16])
		pos += 16
		if pos+int(ln) > len(data) {
			break
		}
		h := make([]byte, ln)
		copy(h, data[pos:pos+int(ln)])
		pos += int(ln)
		nodes[compact.NewNodeID(uint(level), index)] = h
	}
	return nodes
}
