package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
	entrypkg "github.com/Epsilon-Data/epsilon-atl/internal/entry"
	"github.com/Epsilon-Data/epsilon-atl/internal/merkle"
	"github.com/Epsilon-Data/epsilon-atl/internal/sth"
)

// memStore is a minimal in-memory store for testing.
type memStore struct {
	entries   [][]byte
	leafHashs [][]byte
	sths      []*sth.SignedTreeHead
}

func (m *memStore) AppendEntry(entryType int, entryCBOR, leafHash []byte, jobID, teePlatform, submitterID string) (int64, error) {
	idx := int64(len(m.entries))
	m.entries = append(m.entries, entryCBOR)
	m.leafHashs = append(m.leafHashs, leafHash)
	return idx, nil
}

func (m *memStore) GetEntry(index int64) ([]byte, error) {
	if index < 0 || int(index) >= len(m.entries) {
		return nil, &entryNotFoundError{index}
	}
	return m.entries[index], nil
}

func (m *memStore) LeafHashExists(leafHash []byte) (bool, error) {
	for _, h := range m.leafHashs {
		if bytes.Equal(h, leafHash) {
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) SaveSTH(h *sth.SignedTreeHead) error {
	m.sths = append(m.sths, h)
	return nil
}

func (m *memStore) LatestSTH() (*sth.SignedTreeHead, error) {
	if len(m.sths) == 0 {
		return nil, nil
	}
	return m.sths[len(m.sths)-1], nil
}

func (m *memStore) SaveTreeState(size uint64, hashes [][]byte, nodes map[interface{}][]byte) error {
	return nil
}

type entryNotFoundError struct{ index int64 }

func (e *entryNotFoundError) Error() string { return "not found" }

// testableStore wraps memStore to satisfy the Server's store interface
// by providing store.Store-compatible methods through the Server struct.
// Since Server uses store.Store directly, we need a different approach.
// We'll test using httptest and the actual handler.

func setupTestServer(t *testing.T) (*httptest.Server, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	coordPub, coordPriv, _ := ed25519.GenerateKey(nil)
	operatorPub, operatorPriv, _ := ed25519.GenerateKey(nil)

	tree := merkle.NewTree()
	signer := sth.NewSigner(operatorPriv)

	// We can't use store.Store without a database, so we test
	// at the handler level using the Server struct with a mock.
	// For now, test the auth and response helpers directly.
	_ = coordPub
	_ = operatorPub
	_ = signer
	_ = tree

	return nil, coordPub, coordPriv
}

func TestAuthVerification(t *testing.T) {
	coordPub, coordPriv, _ := ed25519.GenerateKey(nil)

	keys := map[string]ed25519.PublicKey{
		"coord-1": coordPub,
	}
	allowed := []string{"coord-1"}

	body := []byte("test-body")
	sig := ed25519.Sign(coordPriv, body)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req := httptest.NewRequest("POST", "/v1/entries", bytes.NewReader(body))
	req.Header.Set("X-Submitter-ID", "coord-1")
	req.Header.Set("X-Coordinator-Signature", sigB64)

	submitter, err := verifyCoordinatorAuth(req, body, allowed, keys)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	if submitter != "coord-1" {
		t.Fatalf("expected coord-1, got %s", submitter)
	}
}

func TestAuthMissingHeaders(t *testing.T) {
	keys := map[string]ed25519.PublicKey{}

	req := httptest.NewRequest("POST", "/v1/entries", nil)
	_, err := verifyCoordinatorAuth(req, nil, nil, keys)
	if err == nil {
		t.Fatal("expected error for missing headers")
	}
}

func TestAuthWrongKey(t *testing.T) {
	coordPub, _, _ := ed25519.GenerateKey(nil)
	_, wrongPriv, _ := ed25519.GenerateKey(nil)

	keys := map[string]ed25519.PublicKey{
		"coord-1": coordPub,
	}

	body := []byte("test-body")
	sig := ed25519.Sign(wrongPriv, body)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req := httptest.NewRequest("POST", "/v1/entries", bytes.NewReader(body))
	req.Header.Set("X-Submitter-ID", "coord-1")
	req.Header.Set("X-Coordinator-Signature", sigB64)

	_, err := verifyCoordinatorAuth(req, body, nil, keys)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestCBORResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeCBOR(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/cbor" {
		t.Fatalf("expected application/cbor, got %s", ct)
	}

	body := w.Body.Bytes()
	var m map[string]string
	if err := entry.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["status"] != "ok" {
		t.Fatalf("expected ok, got %s", m["status"])
	}
}

func TestHealthEndpoint(t *testing.T) {
	// Create a minimal server just for health check
	srv := &Server{mmdSeconds: 3600}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.handleHealth)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/health", nil)
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	body, _ := io.ReadAll(w.Body)
	entrypkg.Unmarshal(body, &resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected ok, got %s", resp["status"])
	}
}

func TestMetadataEndpoint(t *testing.T) {
	srv := &Server{
		operatorPubKeyBytes: []byte("test-pub-key"),
		mmdSeconds:         3600,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/metadata", srv.handleMetadata)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/metadata", nil)
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
