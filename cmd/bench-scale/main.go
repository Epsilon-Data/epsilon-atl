// cmd/bench-scale/main.go — TDSC Figure: ATL latency vs log size.
//
// Runs ATL submission benchmarks at multiple log sizes to produce a
// scalability curve. Seeds entries directly into the database between
// measurement rounds, then restarts measurement at each scale point.
//
// Scale points: 10^3, 10^4, 10^5, 10^6 (configurable)
//
// Output: JSON with per-scale-point stats + LaTeX-ready table + CSV for pgfplots.
//
// Prerequisites:
//   1. ATL server running (empty or pre-existing log — script seeds to target sizes)
//   2. Coordinator signing key
//   3. Database URL (for direct seeding between rounds)
//
// Usage:
//   ATL_URL=http://localhost:8080 \
//   ATL_COORDINATOR_KEY_PATH=./keys/coordinator-bench.key \
//   ATL_SUBMITTER_ID=coordinator-bench \
//   ATL_DATABASE_URL="postgres://atl:atl-bench-2026@localhost:5433/atl?sslmode=disable" \
//   ATL_OPERATOR_KEY_PATH=./keys/operator.key \
//   go run ./cmd/bench-scale --n 50 --output results/scalability.json
package main

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
	"github.com/Epsilon-Data/epsilon-atl/internal/merkle"
	"github.com/Epsilon-Data/epsilon-atl/internal/sth"
	"github.com/Epsilon-Data/epsilon-atl/internal/store"
	"github.com/fxamacker/cbor/v2"
)

// ─── Types ───────────────────────────────────────────────────────────────────

type scalePoint struct {
	TargetLogSize uint64          `json:"target_log_size"`
	ActualLogSize uint64          `json:"actual_log_size"`
	N             int             `json:"n"`
	TotalUS       *latencyStats   `json:"total_us"`
	AuthUS        *latencyStats   `json:"auth_us"`
	LeafHashUS    *latencyStats   `json:"leaf_hash_us"`
	DedupCheckUS  *latencyStats   `json:"dedup_check_us"`
	DBInsertUS    *latencyStats   `json:"db_insert_us"`
	TreeAppendUS  *latencyStats   `json:"tree_append_us"`
	STHSignUS     *latencyStats   `json:"sth_sign_us"`
	StateSaveUS   *latencyStats   `json:"state_save_us"`
	ReceiptGenUS  *latencyStats   `json:"receipt_gen_us"`
	ClientRTTUS   *latencyStats   `json:"client_rtt_us"`
	Samples       []sampleTiming  `json:"samples"`
}

type latencyStats struct {
	Mean float64 `json:"mean"`
	Std  float64 `json:"std"`
	P50  float64 `json:"p50"`
	P95  float64 `json:"p95"`
	P99  float64 `json:"p99"`
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
}

type sampleTiming struct {
	AuthUS       int64 `json:"auth_us"`
	LeafHashUS   int64 `json:"leaf_hash_us"`
	DedupCheckUS int64 `json:"dedup_check_us"`
	DBInsertUS   int64 `json:"db_insert_us"`
	TreeAppendUS int64 `json:"tree_append_us"`
	STHSignUS    int64 `json:"sth_sign_us"`
	StateSaveUS  int64 `json:"state_save_us"`
	ReceiptGenUS int64 `json:"receipt_gen_us"`
	TotalUS      int64 `json:"total_us"`
	ClientRTTUS  int64 `json:"client_rtt_us"`
}

type scalabilityResult struct {
	Timestamp   string       `json:"timestamp"`
	N           int          `json:"n_per_point"`
	PayloadSize int          `json:"payload_bytes"`
	ScalePoints []scalePoint `json:"scale_points"`
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	n := flag.Int("n", 50, "Submissions per scale point")
	warmup := flag.Int("warmup", 5, "Warmup per scale point (discarded)")
	payloadSize := flag.Int("payload-size", 2048, "Attestation payload bytes")
	output := flag.String("output", "", "Output JSON path")
	scalesStr := flag.String("scales", "1000,10000,100000", "Comma-separated target log sizes")
	flag.Parse()

	atlURL := envOrFatal("ATL_URL")
	atlKeyPath := envOrFatal("ATL_COORDINATOR_KEY_PATH")
	submitterID := envOr("ATL_SUBMITTER_ID", "coordinator-bench")
	dbURL := envOrFatal("ATL_DATABASE_URL")
	opKeyPath := envOrFatal("ATL_OPERATOR_KEY_PATH")

	coordKey, err := sth.LoadPrivateKey(atlKeyPath)
	if err != nil {
		log.Fatalf("coordinator key: %v", err)
	}
	opKey, err := sth.LoadPrivateKey(opKeyPath)
	if err != nil {
		log.Fatalf("operator key: %v", err)
	}

	// Parse scale points
	scales := parseScales(*scalesStr)
	if len(scales) == 0 {
		log.Fatal("no scale points specified")
	}

	// Verify ATL
	resp, err := http.Get(atlURL + "/health")
	if err != nil {
		log.Fatalf("ATL unreachable: %v", err)
	}
	resp.Body.Close()

	fmt.Fprintf(os.Stderr, "ATL reachable. Scale points: %v, N=%d per point, payload=%d bytes\n",
		scales, *n, *payloadSize)

	result := scalabilityResult{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		N:           *n,
		PayloadSize: *payloadSize,
	}

	for _, target := range scales {
		fmt.Fprintf(os.Stderr, "\n── Scale point: %d ──\n", target)

		// Seed to target size directly via DB (much faster than HTTP)
		currentSize := getDBTreeSize(dbURL)
		if currentSize < uint64(target) {
			needed := uint64(target) - currentSize
			fmt.Fprintf(os.Stderr, "  Seeding %d entries (current: %d, target: %d)...\n", needed, currentSize, target)
			seedDirect(dbURL, opKey, int(needed))
		}

		// Always restart so ATL rebuilds tree from DB
		fmt.Fprintf(os.Stderr, "  Restarting ATL to rebuild tree...\n")
		restartATL(atlURL)

		// Get actual size from ATL after restart (may differ if rebuild is partial)
		actualSize := getTreeSize(atlURL)
		if actualSize == 0 {
			// Fallback: read from DB directly
			actualSize = getDBTreeSize(dbURL)
		}
		fmt.Fprintf(os.Stderr, "  Log size: %d. Running %d warmup + %d measured...\n", actualSize, *warmup, *n)

		// Warmup
		for i := 0; i < *warmup; i++ {
			submitOne(atlURL, submitterID, coordKey, *payloadSize, actualSize+uint64(i))
		}

		// Measure
		samples := make([]sampleTiming, 0, *n)
		for i := 0; i < *n; i++ {
			seqNum := actualSize + uint64(*warmup) + uint64(i)
			t0 := time.Now()
			timing, err := submitOne(atlURL, submitterID, coordKey, *payloadSize, seqNum)
			rtt := time.Since(t0).Microseconds()
			if err != nil {
				log.Fatalf("  submission %d failed: %v", i, err)
			}
			timing.ClientRTTUS = rtt
			samples = append(samples, *timing)
		}

		sp := scalePoint{
			TargetLogSize: uint64(target),
			ActualLogSize: actualSize,
			N:             *n,
			TotalUS:       computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.TotalUS) })),
			AuthUS:        computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.AuthUS) })),
			LeafHashUS:    computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.LeafHashUS) })),
			DedupCheckUS:  computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.DedupCheckUS) })),
			DBInsertUS:    computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.DBInsertUS) })),
			TreeAppendUS:  computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.TreeAppendUS) })),
			STHSignUS:     computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.STHSignUS) })),
			StateSaveUS:   computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.StateSaveUS) })),
			ReceiptGenUS:  computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.ReceiptGenUS) })),
			ClientRTTUS:   computeStats(extractSamples(samples, func(s sampleTiming) float64 { return float64(s.ClientRTTUS) })),
			Samples:       samples,
		}
		result.ScalePoints = append(result.ScalePoints, sp)

		fmt.Fprintf(os.Stderr, "  total_mean=%.0fµs  dedup=%.0fµs  db_insert=%.0fµs  tree_append=%.0fµs\n",
			sp.TotalUS.Mean, sp.DedupCheckUS.Mean, sp.DBInsertUS.Mean, sp.TreeAppendUS.Mean)
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.MkdirAll(filepath.Dir(*output), 0755)
		os.WriteFile(*output, out, 0644)
		fmt.Fprintf(os.Stderr, "\nResults written to %s\n", *output)
	} else {
		fmt.Println(string(out))
	}

	printScalabilitySummary(result)
}

// ─── Direct DB Seeding (bypasses HTTP for speed) ─────────────────────────────

func seedDirect(dbURL string, opKey ed25519.PrivateKey, count int) {
	s, err := store.New(dbURL)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer s.Close()
	s.EnsureSchema()

	signer := sth.NewSigner(opKey)
	tree := merkle.NewTree()

	// Rebuild existing tree
	dbSize, _ := s.TreeSize()
	if dbSize > 0 {
		tree.RebuildNodeCache(s.IterateLeafHashes)
	}

	batchSize := 1000
	for i := 0; i < count; i++ {
		jobID := fmt.Sprintf("SCALE-%012d", tree.Size()+1)
		nonce := make([]byte, 32)
		rand.Read(nonce)
		attestation := make([]byte, 64) // small for seeding speed
		rand.Read(attestation)

		data, _ := entry.Marshal(entry.HAEntry{
			EntryType:   entry.EntryTypeHA,
			JobID:       jobID,
			TEEPlatform: "aws-nitro",
			Attestation: attestation,
			Nonce:       nonce,
			SubmitterID: "coordinator-bench",
		})
		leafHash := merkle.HashLeaf(data)
		_, err := s.AppendEntry(entry.EntryTypeHA, data, leafHash, jobID, "aws-nitro", "coordinator-bench")
		if err != nil {
			continue // skip dupes
		}
		tree.Append(leafHash)

		if (i+1)%batchSize == 0 {
			fmt.Fprintf(os.Stderr, "    seeded %d/%d\n", i+1, count)
		}
	}

	// Sign final STH
	root, _ := tree.RootHash()
	if root != nil {
		sthVal, _ := signer.Sign(tree.Size(), root)
		s.SaveSTH(sthVal)
		size, hashes := tree.CompactState()
		s.SaveTreeState(size, hashes, nil)
	}
}

// restartATL restarts the ATL container so it rebuilds its Merkle tree from DB.
// Direct seeding bypasses the server, so a restart is required.
func restartATL(atlURL string) {
	fmt.Fprintf(os.Stderr, "  Restarting atl-server container...\n")
	cmd := exec.Command("docker", "compose", "restart", "atl")
	cmd.Dir = envOr("ATL_COMPOSE_DIR", ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "  WARNING: docker compose restart failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "  Manually run: docker compose restart atl\n")
	}

	// Poll until ATL is healthy
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		resp, err := http.Get(atlURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Fprintf(os.Stderr, "  ATL healthy after restart.\n")
				return
			}
		}
	}
	log.Fatal("ATL did not become healthy after restart")
}

// ─── ATL HTTP Client ─────────────────────────────────────────────────────────

func submitOne(atlURL, submitterID string, privKey ed25519.PrivateKey, payloadSize int, seqNum uint64) (*sampleTiming, error) {
	attestation := make([]byte, payloadSize)
	rand.Read(attestation)
	nonce := make([]byte, 32)
	rand.Read(nonce)

	ha := entry.HAEntry{
		EntryType:   entry.EntryTypeHA,
		JobID:       fmt.Sprintf("SCALE-M-%012d", seqNum),
		TEEPlatform: "aws-nitro",
		Attestation: attestation,
		Nonce:       nonce,
		SubmitterID: submitterID,
	}
	body, _ := entry.Marshal(ha)
	sig := ed25519.Sign(privKey, body)

	req, _ := http.NewRequest("POST", atlURL+"/v1/entries", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("X-Submitter-ID", submitterID)
	req.Header.Set("X-Coordinator-Signature", base64.StdEncoding.EncodeToString(sig))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	var respMap map[interface{}]interface{}
	cbor.Unmarshal(respBody, &respMap)

	timing := &sampleTiming{}
	if tm, ok := respMap["timing"]; ok {
		if m, ok := tm.(map[interface{}]interface{}); ok {
			timing.AuthUS = toInt64(m["auth_us"])
			timing.LeafHashUS = toInt64(m["leaf_hash_us"])
			timing.DedupCheckUS = toInt64(m["dedup_check_us"])
			timing.DBInsertUS = toInt64(m["db_insert_us"])
			timing.TreeAppendUS = toInt64(m["tree_append_us"])
			timing.STHSignUS = toInt64(m["sth_sign_us"])
			timing.StateSaveUS = toInt64(m["state_save_us"])
			timing.ReceiptGenUS = toInt64(m["receipt_gen_us"])
			timing.TotalUS = toInt64(m["total_us"])
		}
	}
	return timing, nil
}

func getDBTreeSize(dbURL string) uint64 {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return 0
	}
	defer db.Close()
	var count uint64
	if err := db.QueryRow("SELECT COUNT(*) FROM atl_entries").Scan(&count); err != nil {
		return 0
	}
	return count
}

func getTreeSize(atlURL string) uint64 {
	resp, err := http.Get(atlURL + "/v1/sth")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return 0
	}
	body, _ := io.ReadAll(resp.Body)
	var m map[interface{}]interface{}
	cbor.Unmarshal(body, &m)
	return toUint64(m["tree_size"])
}

// ─── Output ──────────────────────────────────────────────────────────────────

func printScalabilitySummary(r scalabilityResult) {
	fmt.Fprintf(os.Stderr, "\n=== TDSC Figure: ATL Submission Latency vs Log Size ===\n")
	fmt.Fprintf(os.Stderr, "N=%d per point | Payload: %d bytes\n\n", r.N, r.PayloadSize)

	fmt.Fprintf(os.Stderr, "%-12s %10s %10s %10s %10s %10s %10s\n",
		"Log Size", "Total(µs)", "Dedup(µs)", "Insert(µs)", "TreeApp(µs)", "STH(µs)", "State(µs)")
	fmt.Fprintf(os.Stderr, "%s\n", "-----------------------------------------------------------------------------------------")

	for _, sp := range r.ScalePoints {
		fmt.Fprintf(os.Stderr, "%-12d %10.0f %10.0f %10.0f %10.0f %10.0f %10.0f\n",
			sp.ActualLogSize,
			sp.TotalUS.Mean,
			sp.DedupCheckUS.Mean,
			sp.DBInsertUS.Mean,
			sp.TreeAppendUS.Mean,
			sp.STHSignUS.Mean,
			sp.StateSaveUS.Mean,
		)
	}

	// CSV for pgfplots
	fmt.Fprintf(os.Stderr, "\n%% pgfplots CSV (paste into .csv file):\n")
	fmt.Fprintf(os.Stderr, "log_size,total_mean,total_p50,total_p95,dedup_mean,insert_mean,tree_append_mean,sth_sign_mean,state_save_mean\n")
	for _, sp := range r.ScalePoints {
		fmt.Fprintf(os.Stderr, "%d,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f\n",
			sp.ActualLogSize,
			sp.TotalUS.Mean, sp.TotalUS.P50, sp.TotalUS.P95,
			sp.DedupCheckUS.Mean, sp.DBInsertUS.Mean,
			sp.TreeAppendUS.Mean, sp.STHSignUS.Mean, sp.StateSaveUS.Mean,
		)
	}

	// LaTeX table
	fmt.Fprintf(os.Stderr, "\n%% LaTeX table rows:\n")
	for _, sp := range r.ScalePoints {
		fmt.Fprintf(os.Stderr, "$10^{%d}$ & %.0f & %.0f & %.0f & %.0f & %.0f & %.0f \\\\\n",
			intLog10(sp.ActualLogSize),
			sp.TotalUS.Mean, sp.DedupCheckUS.Mean, sp.DBInsertUS.Mean,
			sp.TreeAppendUS.Mean, sp.STHSignUS.Mean, sp.StateSaveUS.Mean,
		)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func parseScales(s string) []int {
	var result []int
	current := 0
	for _, c := range s {
		if c == ',' {
			if current > 0 {
				result = append(result, current)
			}
			current = 0
		} else if c >= '0' && c <= '9' {
			current = current*10 + int(c-'0')
		}
	}
	if current > 0 {
		result = append(result, current)
	}
	return result
}

func intLog10(n uint64) int {
	if n == 0 {
		return 0
	}
	count := 0
	for n >= 10 {
		n /= 10
		count++
	}
	return count
}

func extractSamples(samples []sampleTiming, fn func(sampleTiming) float64) []float64 {
	vals := make([]float64, len(samples))
	for i, s := range samples {
		vals[i] = fn(s)
	}
	return vals
}

func computeStats(vals []float64) *latencyStats {
	if len(vals) == 0 {
		return &latencyStats{}
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

	return &latencyStats{
		Mean: math.Round(mean*100) / 100,
		Std:  math.Round(std*100) / 100,
		P50:  percentile(sorted, 0.50),
		P95:  percentile(sorted, 0.95),
		P99:  percentile(sorted, 0.99),
		Min:  sorted[0],
		Max:  sorted[len(sorted)-1],
	}
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
