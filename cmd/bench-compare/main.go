// cmd/bench-compare/main.go — TDSC Table 9: ATL vs Signed Database comparison.
//
// Implements a simple signed-DB baseline (Ed25519 per-row signature)
// and benchmarks it against the running ATL server.
//
// Comparison dimensions:
//   - Write latency
//   - Proof generation time
//   - Proof size (bytes)
//   - Tamper detection method
//   - Offline verification capability
//
// Prerequisites:
//   1. ATL server running with pre-seeded data
//   2. PostgreSQL accessible at SIGNED_DB_URL (creates its own table)
//   3. Coordinator key for ATL submissions
//
// Usage:
//   ATL_URL=http://localhost:8080 \
//   ATL_COORDINATOR_KEY_PATH=./keys/coordinator-bench.key \
//   SIGNED_DB_URL="postgres://atl:atl-bench-2026@localhost:5433/atl?sslmode=disable" \
//   go run ./cmd/bench-compare --n 100 --payload-size 2048 --output results/table9.json
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
	"github.com/Epsilon-Data/epsilon-atl/internal/sth"
	"github.com/fxamacker/cbor/v2"
	_ "github.com/lib/pq"
)

// ─── Signed-DB Baseline ─────────────────────────────────────────────────────

// signedDBRow represents a row in the signed_entries table.
// Each row is independently signed — no tree structure, no global state.
type signedDBRow struct {
	ID        int64
	EntryCBOR []byte
	EntryHash []byte // SHA-256(entry_cbor)
	Signature []byte // Ed25519(entry_hash)
}

// signedDBProof is a "proof" for the signed-DB baseline:
// just the row signature + the entry hash. No tree path.
type signedDBProof struct {
	EntryHash []byte `json:"entry_hash"`
	Signature []byte `json:"signature"`
}

func setupSignedDB(dbURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS signed_entries (
			id         BIGSERIAL PRIMARY KEY,
			entry_cbor BYTEA NOT NULL,
			entry_hash BYTEA NOT NULL,
			signature  BYTEA NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("creating signed_entries table: %w", err)
	}
	// Clear previous benchmark data
	_, _ = db.Exec(`TRUNCATE signed_entries`)
	return db, nil
}

func signedDBWrite(db *sql.DB, privKey ed25519.PrivateKey, entryCBOR []byte) (writeUS int64, row *signedDBRow, err error) {
	t0 := time.Now()

	h := sha256.Sum256(entryCBOR)
	entryHash := h[:]
	sig := ed25519.Sign(privKey, entryHash)

	var id int64
	err = db.QueryRow(
		`INSERT INTO signed_entries (entry_cbor, entry_hash, signature) VALUES ($1, $2, $3) RETURNING id`,
		entryCBOR, entryHash, sig,
	).Scan(&id)

	writeUS = time.Since(t0).Microseconds()

	if err != nil {
		return writeUS, nil, err
	}

	return writeUS, &signedDBRow{
		ID:        id,
		EntryCBOR: entryCBOR,
		EntryHash: entryHash,
		Signature: sig,
	}, nil
}

func signedDBProofGen(db *sql.DB, id int64) (proofUS int64, proof *signedDBProof, proofSize int, err error) {
	t0 := time.Now()

	var entryHash, signature []byte
	err = db.QueryRow(
		`SELECT entry_hash, signature FROM signed_entries WHERE id = $1`, id,
	).Scan(&entryHash, &signature)

	proofUS = time.Since(t0).Microseconds()
	if err != nil {
		return proofUS, nil, 0, err
	}

	proof = &signedDBProof{
		EntryHash: entryHash,
		Signature: signature,
	}
	proofBytes, _ := json.Marshal(proof)
	return proofUS, proof, len(proofBytes), nil
}

func signedDBVerify(pubKey ed25519.PublicKey, entryCBOR []byte, proof *signedDBProof) (verifyUS int64, valid bool) {
	t0 := time.Now()

	// Recompute hash from entry
	h := sha256.Sum256(entryCBOR)
	recomputedHash := h[:]

	// Check hash matches
	if !bytes.Equal(recomputedHash, proof.EntryHash) {
		return time.Since(t0).Microseconds(), false
	}

	// Verify signature
	valid = ed25519.Verify(pubKey, proof.EntryHash, proof.Signature)
	return time.Since(t0).Microseconds(), valid
}

// ─── ATL Client (reused from cmd/bench) ──────────────────────────────────────

func atlWrite(atlURL, submitterID string, privKey ed25519.PrivateKey, entryCBOR []byte) (writeUS int64, leafIndex int64, treeSize uint64, receiptSize int, err error) {
	sig := ed25519.Sign(privKey, entryCBOR)

	req, err := http.NewRequest("POST", atlURL+"/v1/entries", bytes.NewReader(entryCBOR))
	if err != nil {
		return 0, 0, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("X-Submitter-ID", submitterID)
	req.Header.Set("X-Coordinator-Signature", base64.StdEncoding.EncodeToString(sig))

	t0 := time.Now()
	resp, err := http.DefaultClient.Do(req)
	writeUS = time.Since(t0).Microseconds()

	if err != nil {
		return writeUS, 0, 0, 0, fmt.Errorf("POST: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		return writeUS, 0, 0, 0, fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	var respMap map[interface{}]interface{}
	if err := cbor.Unmarshal(respBody, &respMap); err != nil {
		return writeUS, 0, 0, 0, fmt.Errorf("decode: %w", err)
	}

	leafIndex = toInt64(respMap["leaf_index"])
	treeSize = toUint64(respMap["tree_size"])
	if r, ok := respMap["receipt"]; ok {
		if rb, ok := r.([]byte); ok {
			receiptSize = len(rb)
		}
	}
	return writeUS, leafIndex, treeSize, receiptSize, nil
}

func atlProofGen(atlURL string, leafIndex, treeSize uint64) (proofUS int64, proofSize int, err error) {
	url := fmt.Sprintf("%s/v1/entries/%d/proof?tree_size=%d", atlURL, leafIndex, treeSize)

	t0 := time.Now()
	resp, err := http.Get(url)
	proofUS = time.Since(t0).Microseconds()

	if err != nil {
		return proofUS, 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return proofUS, 0, fmt.Errorf("proof status %d", resp.StatusCode)
	}
	return proofUS, len(body), nil
}

// ─── Benchmark Runner ────────────────────────────────────────────────────────

type samplePair struct {
	Index int `json:"index"`
	// Signed-DB
	SDB_WriteUS    int64 `json:"sdb_write_us"`
	SDB_ProofGenUS int64 `json:"sdb_proof_gen_us"`
	SDB_ProofSize  int   `json:"sdb_proof_size"`
	SDB_VerifyUS   int64 `json:"sdb_verify_us"`
	// ATL
	ATL_WriteUS    int64  `json:"atl_write_us"`
	ATL_ProofGenUS int64  `json:"atl_proof_gen_us"`
	ATL_ProofSize  int    `json:"atl_proof_size"`
	ATL_ReceiptSize int   `json:"atl_receipt_size"`
	ATL_TreeSize   uint64 `json:"atl_tree_size"`
}

type comparisonStats struct {
	Mean float64 `json:"mean_us"`
	Std  float64 `json:"std_us"`
	P50  float64 `json:"p50_us"`
	P95  float64 `json:"p95_us"`
}

type comparisonResult struct {
	Timestamp   string `json:"timestamp"`
	N           int    `json:"n"`
	PayloadSize int    `json:"payload_bytes"`

	// Signed-DB stats
	SDB_Write    *comparisonStats `json:"sdb_write"`
	SDB_ProofGen *comparisonStats `json:"sdb_proof_gen"`
	SDB_ProofSizeAvg int          `json:"sdb_proof_size_avg_bytes"`
	SDB_Verify   *comparisonStats `json:"sdb_verify"`

	// ATL stats
	ATL_Write    *comparisonStats `json:"atl_write"`
	ATL_ProofGen *comparisonStats `json:"atl_proof_gen"`
	ATL_ProofSizeAvg int          `json:"atl_proof_size_avg_bytes"`
	ATL_ReceiptSizeAvg int        `json:"atl_receipt_size_avg_bytes"`

	// Feature comparison
	Features map[string][2]string `json:"features"`

	Samples []samplePair `json:"samples"`
}

func main() {
	n := flag.Int("n", 100, "Number of measured operations")
	warmup := flag.Int("warmup", 10, "Warmup iterations (discarded)")
	payloadSize := flag.Int("payload-size", 2048, "Attestation payload bytes")
	output := flag.String("output", "", "Output JSON path")
	flag.Parse()

	atlURL := envOrFatal("ATL_URL")
	atlKeyPath := envOrFatal("ATL_COORDINATOR_KEY_PATH")
	submitterID := envOr("ATL_SUBMITTER_ID", "coordinator-bench")
	signedDBURL := envOrFatal("SIGNED_DB_URL")

	atlKey, err := sth.LoadPrivateKey(atlKeyPath)
	if err != nil {
		log.Fatalf("ATL key: %v", err)
	}

	// Generate separate key for signed-DB baseline (operator signs rows)
	sdbPub, sdbPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}

	// Setup signed-DB
	sdb, err := setupSignedDB(signedDBURL)
	if err != nil {
		log.Fatalf("signed-DB: %v", err)
	}
	defer sdb.Close()

	// Verify ATL
	resp, err := http.Get(atlURL + "/health")
	if err != nil {
		log.Fatalf("ATL unreachable: %v", err)
	}
	resp.Body.Close()

	fmt.Fprintf(os.Stderr, "Both systems ready. Running %d warmup + %d measured (payload: %d bytes)\n", *warmup, *n, *payloadSize)

	// Generate all entries upfront so both systems get identical payloads
	allEntries := make([][]byte, *warmup+*n)
	for i := range allEntries {
		attestation := make([]byte, *payloadSize)
		rand.Read(attestation)
		nonce := make([]byte, 32)
		rand.Read(nonce)
		ha := entry.HAEntry{
			EntryType:   entry.EntryTypeHA,
			JobID:       fmt.Sprintf("CMP-%012d", i),
			TEEPlatform: "aws-nitro",
			Attestation: attestation,
			Nonce:       nonce,
			SubmitterID: submitterID,
		}
		allEntries[i], _ = entry.Marshal(ha)
	}

	// ── Warmup ──
	for i := 0; i < *warmup; i++ {
		signedDBWrite(sdb, sdbPriv, allEntries[i])
		atlWrite(atlURL, submitterID, atlKey, allEntries[i])
	}
	fmt.Fprintf(os.Stderr, "Warmup done.\n")

	// ── Measured ──
	samples := make([]samplePair, 0, *n)

	for i := 0; i < *n; i++ {
		idx := *warmup + i
		entryCBOR := allEntries[idx]
		sp := samplePair{Index: i}

		// --- Signed-DB: write ---
		sdbWriteUS, sdbRow, err := signedDBWrite(sdb, sdbPriv, entryCBOR)
		if err != nil {
			log.Fatalf("sdb write %d: %v", i, err)
		}
		sp.SDB_WriteUS = sdbWriteUS

		// --- Signed-DB: proof generation ---
		sdbProofUS, sdbProof, sdbProofSize, err := signedDBProofGen(sdb, sdbRow.ID)
		if err != nil {
			log.Fatalf("sdb proof %d: %v", i, err)
		}
		sp.SDB_ProofGenUS = sdbProofUS
		sp.SDB_ProofSize = sdbProofSize

		// --- Signed-DB: verify ---
		sdbVerifyUS, valid := signedDBVerify(sdbPub, entryCBOR, sdbProof)
		if !valid {
			log.Fatalf("sdb verify %d: invalid", i)
		}
		sp.SDB_VerifyUS = sdbVerifyUS

		// --- ATL: write (includes receipt in response) ---
		// Use a different entry to avoid dedup (append unique suffix)
		atlEntryNonce := make([]byte, 32)
		rand.Read(atlEntryNonce)
		atlHA := entry.HAEntry{
			EntryType:   entry.EntryTypeHA,
			JobID:       fmt.Sprintf("CMP-ATL-%012d", idx),
			TEEPlatform: "aws-nitro",
			Attestation: entryCBOR[10:], // reuse bulk of payload
			Nonce:       atlEntryNonce,
			SubmitterID: submitterID,
		}
		atlEntryCBOR, _ := entry.Marshal(atlHA)

		atlWriteUS, leafIndex, treeSize, receiptSize, err := atlWrite(atlURL, submitterID, atlKey, atlEntryCBOR)
		if err != nil {
			log.Fatalf("atl write %d: %v", i, err)
		}
		sp.ATL_WriteUS = atlWriteUS
		sp.ATL_ReceiptSize = receiptSize
		sp.ATL_TreeSize = treeSize

		// --- ATL: proof generation ---
		atlProofUS, atlProofSize, err := atlProofGen(atlURL, uint64(leafIndex), treeSize)
		if err != nil {
			log.Fatalf("atl proof %d: %v", i, err)
		}
		sp.ATL_ProofGenUS = atlProofUS
		sp.ATL_ProofSize = atlProofSize

		samples = append(samples, sp)

		if (i+1)%10 == 0 {
			fmt.Fprintf(os.Stderr, "  %d/%d  sdb_write=%dµs  atl_write=%dµs\n",
				i+1, *n, sp.SDB_WriteUS, sp.ATL_WriteUS)
		}
	}

	// ── Compute results ──
	result := comparisonResult{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		N:           *n,
		PayloadSize: *payloadSize,

		SDB_Write:    stats(samples, func(s samplePair) float64 { return float64(s.SDB_WriteUS) }),
		SDB_ProofGen: stats(samples, func(s samplePair) float64 { return float64(s.SDB_ProofGenUS) }),
		SDB_ProofSizeAvg: avgInt(samples, func(s samplePair) int { return s.SDB_ProofSize }),
		SDB_Verify:   stats(samples, func(s samplePair) float64 { return float64(s.SDB_VerifyUS) }),

		ATL_Write:    stats(samples, func(s samplePair) float64 { return float64(s.ATL_WriteUS) }),
		ATL_ProofGen: stats(samples, func(s samplePair) float64 { return float64(s.ATL_ProofGenUS) }),
		ATL_ProofSizeAvg: avgInt(samples, func(s samplePair) int { return s.ATL_ProofSize }),
		ATL_ReceiptSizeAvg: avgInt(samples, func(s samplePair) int { return s.ATL_ReceiptSize }),

		Features: map[string][2]string{
			"tamper_detection":    {"Per-row signature only", "Append-only Merkle tree + consistency proofs"},
			"deletion_detection":  {"None (operator can delete rows)", "Monitors detect via STH consistency"},
			"offline_verify":      {"Yes (pubkey + signature)", "Yes (receipt + operator pubkey)"},
			"public_auditability": {"No (requires DB access)", "Yes (public GET endpoints)"},
			"ordering_guarantee":  {"None (DB can reorder)", "Cryptographic (Merkle tree)"},
			"historical_proofs":   {"No", "Yes (consistency proofs between any two tree sizes)"},
		},

		Samples: samples,
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.MkdirAll(filepath.Dir(*output), 0755)
		os.WriteFile(*output, out, 0644)
		fmt.Fprintf(os.Stderr, "\nResults written to %s\n", *output)
	} else {
		fmt.Println(string(out))
	}

	printTable9(result)
}

func printTable9(r comparisonResult) {
	fmt.Fprintf(os.Stderr, "\n=== TDSC Table 9: ATL vs Signed Database ===\n")
	fmt.Fprintf(os.Stderr, "N=%d | Payload: %d bytes\n\n", r.N, r.PayloadSize)

	fmt.Fprintf(os.Stderr, "%-25s %15s %15s\n", "Metric", "Signed-DB", "ATL")
	fmt.Fprintf(os.Stderr, "%s\n", "-----------------------------------------------------------")
	fmt.Fprintf(os.Stderr, "%-25s %12.0f µs %12.0f µs\n", "Write latency (mean)", r.SDB_Write.Mean, r.ATL_Write.Mean)
	fmt.Fprintf(os.Stderr, "%-25s %12.0f µs %12.0f µs\n", "Write latency (P50)", r.SDB_Write.P50, r.ATL_Write.P50)
	fmt.Fprintf(os.Stderr, "%-25s %12.0f µs %12.0f µs\n", "Proof gen (mean)", r.SDB_ProofGen.Mean, r.ATL_ProofGen.Mean)
	fmt.Fprintf(os.Stderr, "%-25s %12d B %12d B\n", "Proof size", r.SDB_ProofSizeAvg, r.ATL_ProofSizeAvg)
	fmt.Fprintf(os.Stderr, "%-25s %12s %12d B\n", "Receipt size", "N/A", r.ATL_ReceiptSizeAvg)
	fmt.Fprintf(os.Stderr, "%-25s %12.0f µs %12s\n", "Verify (offline)", r.SDB_Verify.Mean, "receipt-based")

	fmt.Fprintf(os.Stderr, "\n%-25s %15s %15s\n", "Feature", "Signed-DB", "ATL")
	fmt.Fprintf(os.Stderr, "%s\n", "-----------------------------------------------------------")
	featureOrder := []string{"tamper_detection", "deletion_detection", "offline_verify", "public_auditability", "ordering_guarantee", "historical_proofs"}
	for _, k := range featureOrder {
		v := r.Features[k]
		fmt.Fprintf(os.Stderr, "%-25s %-28s %s\n", k, v[0], v[1])
	}

	// LaTeX
	fmt.Fprintf(os.Stderr, "\n%% LaTeX rows:\n")
	fmt.Fprintf(os.Stderr, "Write latency (µs) & %.0f & %.0f \\\\\n", r.SDB_Write.Mean, r.ATL_Write.Mean)
	fmt.Fprintf(os.Stderr, "Proof generation (µs) & %.0f & %.0f \\\\\n", r.SDB_ProofGen.Mean, r.ATL_ProofGen.Mean)
	fmt.Fprintf(os.Stderr, "Proof size (B) & %d & %d \\\\\n", r.SDB_ProofSizeAvg, r.ATL_ProofSizeAvg)
	fmt.Fprintf(os.Stderr, "Tamper detection & Per-row sig & Merkle tree \\\\\n")
	fmt.Fprintf(os.Stderr, "Deletion detection & None & STH consistency \\\\\n")
	fmt.Fprintf(os.Stderr, "Offline verification & \\checkmark & \\checkmark \\\\\n")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func stats(samples []samplePair, fn func(samplePair) float64) *comparisonStats {
	vals := make([]float64, len(samples))
	for i, s := range samples {
		vals[i] = fn(s)
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)

	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))

	var sumSq float64
	for _, v := range vals {
		d := v - mean
		sumSq += d * d
	}
	std := math.Sqrt(sumSq / float64(len(vals)))

	return &comparisonStats{
		Mean: math.Round(mean*100) / 100,
		Std:  math.Round(std*100) / 100,
		P50:  percentile(sorted, 0.50),
		P95:  percentile(sorted, 0.95),
	}
}

func avgInt(samples []samplePair, fn func(samplePair) int) int {
	if len(samples) == 0 {
		return 0
	}
	var sum int
	for _, s := range samples {
		sum += fn(s)
	}
	return sum / len(samples)
}

func percentile(sorted []float64, p float64) float64 {
	idx := p * float64(len(sorted)-1)
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	if lower == upper || upper >= len(sorted) {
		return sorted[lower]
	}
	frac := idx - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

func toInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	default:
		return 0
	}
}

func toUint64(v interface{}) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		return uint64(n)
	default:
		return 0
	}
}

func envOrFatal(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s required", key)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
