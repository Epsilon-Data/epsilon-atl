package store

import (
	"os"
	"testing"

	"github.com/Epsilon-Data/epsilon-atl/internal/sth"
	"github.com/transparency-dev/merkle/compact"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dbURL := os.Getenv("ATL_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("ATL_TEST_DB_URL not set, skipping integration test")
	}
	s, err := New(dbURL)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.EnsureSchema(); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	t.Cleanup(func() {
		s.db.Exec("DELETE FROM atl_entries")
		s.db.Exec("DELETE FROM tree_heads")
		s.db.Exec("DELETE FROM tree_state")
		s.Close()
	})
	return s
}

func TestEntryRoundtrip(t *testing.T) {
	s := testStore(t)
	cbor := []byte{0xa2, 0x00, 0x01, 0x01, 0x63, 0x66, 0x6f, 0x6f}
	hash := []byte("deadbeef12345678deadbeef12345678")

	idx, err := s.AppendEntry(1, cbor, hash, "job-1", "nitro", "coord-1")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if idx != 0 {
		t.Fatalf("expected index 0, got %d", idx)
	}

	got, err := s.GetEntry(0)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != string(cbor) {
		t.Fatalf("entry mismatch")
	}
}

func TestDuplicateHashRejection(t *testing.T) {
	s := testStore(t)
	hash := []byte("unique-hash-0000unique-hash-0000")
	s.AppendEntry(1, []byte{0x01}, hash, "", "", "c")
	_, err := s.AppendEntry(1, []byte{0x01}, hash, "", "", "c")
	if err == nil {
		t.Fatal("expected duplicate hash rejection")
	}
}

func TestLeafHashExists(t *testing.T) {
	s := testStore(t)
	hash := []byte("exists-test-hash-32-bytes-long!!")
	exists, _ := s.LeafHashExists(hash)
	if exists {
		t.Fatal("should not exist yet")
	}
	s.AppendEntry(1, []byte{0x01}, hash, "", "", "c")
	exists, _ = s.LeafHashExists(hash)
	if !exists {
		t.Fatal("should exist after insert")
	}
}

func TestSTHCrud(t *testing.T) {
	s := testStore(t)

	// No STH initially
	h, err := s.LatestSTH()
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if h != nil {
		t.Fatal("expected nil STH initially")
	}

	sthVal := &sth.SignedTreeHead{
		TreeSize:  5,
		RootHash:  []byte("roothash12345678roothash12345678"),
		Timestamp: 1700000000,
		Signature: []byte("sig-placeholder"),
	}
	if err := s.SaveSTH(sthVal); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.LatestSTH()
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if got.TreeSize != 5 {
		t.Fatalf("tree size mismatch: %d", got.TreeSize)
	}

	bySize, err := s.GetSTHBySize(5)
	if err != nil {
		t.Fatalf("by size: %v", err)
	}
	if bySize == nil || bySize.TreeSize != 5 {
		t.Fatal("get by size failed")
	}
}

func TestTreeStateRoundtrip(t *testing.T) {
	s := testStore(t)

	hashes := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06},
	}
	nodes := map[compact.NodeID][]byte{
		compact.NewNodeID(0, 0): {0xAA},
		compact.NewNodeID(1, 0): {0xBB},
	}
	if err := s.SaveTreeState(10, hashes, nodes); err != nil {
		t.Fatalf("save: %v", err)
	}

	size, gotHashes, gotNodes, err := s.LoadTreeState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if size != 10 {
		t.Fatalf("size mismatch: %d", size)
	}
	if len(gotHashes) != 2 {
		t.Fatalf("hashes count mismatch: %d", len(gotHashes))
	}
	if len(gotNodes) != 2 {
		t.Fatalf("nodes count mismatch: %d", len(gotNodes))
	}
}
