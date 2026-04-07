// cmd/bench/main.go — TDSC Table 5: ATL submission latency decomposition.
//
// Prerequisites:
//   1. ATL server running with pre-seeded log (use cmd/seed --count 1000000)
//   2. Coordinator signing key at ATL_COORDINATOR_KEY_PATH
//
// Usage:
//   ATL_URL=http://localhost:8080 \
//   ATL_COORDINATOR_KEY_PATH=./keys/coordinator-bench.key \
//   ATL_SUBMITTER_ID=coordinator-bench \
//   go run ./cmd/bench --n 100 --payload-size 2048 --warmup 10 --output results/table5.json
package main

import (
	"bytes"
	"crypto/ed25519"
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
	"path/filepath"
	"sort"
	"time"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
	"github.com/Epsilon-Data/epsilon-atl/internal/sth"
	"github.com/fxamacker/cbor/v2"
)

type config struct {
	N           int
	Warmup      int
	PayloadSize int
	ATLURL      string
	KeyPath     string
	SubmitterID string
	Output      string
}

// serverTiming matches the timing map returned by handleSubmitEntry.
type serverTiming struct {
	AuthUS       int64 `json:"auth_us"`
	PolicyUS     int64 `json:"policy_us"`
	LeafHashUS   int64 `json:"leaf_hash_us"`
	DedupCheckUS int64 `json:"dedup_check_us"`
	DBInsertUS   int64 `json:"db_insert_us"`
	TreeAppendUS int64 `json:"tree_append_us"`
	STHSignUS    int64 `json:"sth_sign_us"`
	StateSaveUS  int64 `json:"state_save_us"`
	ReceiptGenUS int64 `json:"receipt_gen_us"`
	TotalUS      int64 `json:"total_us"`
}

type sampleResult struct {
	Index        int           `json:"index"`
	LeafIndex    int64         `json:"leaf_index"`
	TreeSize     uint64        `json:"tree_size"`
	ClientRTTUS  int64         `json:"client_rtt_us"`
	ServerTiming serverTiming  `json:"server_timing"`
}

type stepStats struct {
	Mean float64 `json:"mean_us"`
	Std  float64 `json:"std_us"`
	P50  float64 `json:"p50_us"`
	P95  float64 `json:"p95_us"`
	P99  float64 `json:"p99_us"`
	Min  float64 `json:"min_us"`
	Max  float64 `json:"max_us"`
}

type benchmarkResult struct {
	Timestamp     string                `json:"timestamp"`
	N             int                   `json:"n"`
	Warmup        int                   `json:"warmup"`
	PayloadSize   int                   `json:"payload_bytes"`
	LogSizeStart  uint64                `json:"log_size_start"`
	LogSizeEnd    uint64                `json:"log_size_end"`
	Steps         map[string]*stepStats `json:"steps"`
	ClientRTT     *stepStats            `json:"client_rtt"`
	Samples       []sampleResult        `json:"samples"`
}

func main() {
	cfg := config{}
	flag.IntVar(&cfg.N, "n", 100, "Number of measured submissions")
	flag.IntVar(&cfg.Warmup, "warmup", 10, "Warmup submissions (discarded)")
	flag.IntVar(&cfg.PayloadSize, "payload-size", 2048, "Synthetic attestation payload size in bytes (realistic Nitro doc ~2-4KB)")
	flag.StringVar(&cfg.Output, "output", "", "Output JSON path (default: stdout)")
	flag.Parse()

	cfg.ATLURL = envOrFatal("ATL_URL")
	cfg.KeyPath = envOrFatal("ATL_COORDINATOR_KEY_PATH")
	cfg.SubmitterID = envOr("ATL_SUBMITTER_ID", "coordinator-bench")

	privKey, err := sth.LoadPrivateKey(cfg.KeyPath)
	if err != nil {
		log.Fatalf("loading coordinator key: %v", err)
	}

	// Verify ATL is reachable
	resp, err := http.Get(cfg.ATLURL + "/health")
	if err != nil {
		log.Fatalf("ATL unreachable at %s: %v", cfg.ATLURL, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatalf("ATL health check failed: %d", resp.StatusCode)
	}

	// Get current tree size
	startSize := getTreeSize(cfg.ATLURL)
	fmt.Fprintf(os.Stderr, "ATL reachable. Current log size: %d\n", startSize)
	fmt.Fprintf(os.Stderr, "Running %d warmup + %d measured submissions (payload: %d bytes)\n", cfg.Warmup, cfg.N, cfg.PayloadSize)

	// Warmup
	for i := 0; i < cfg.Warmup; i++ {
		_, err := submitOne(cfg.ATLURL, cfg.SubmitterID, privKey, cfg.PayloadSize, startSize+uint64(i))
		if err != nil {
			log.Fatalf("warmup %d failed: %v", i, err)
		}
	}
	fmt.Fprintf(os.Stderr, "Warmup done. Starting measurement...\n")

	// Measured submissions
	samples := make([]sampleResult, 0, cfg.N)
	for i := 0; i < cfg.N; i++ {
		seqNum := startSize + uint64(cfg.Warmup) + uint64(i)

		t0 := time.Now()
		result, err := submitOne(cfg.ATLURL, cfg.SubmitterID, privKey, cfg.PayloadSize, seqNum)
		clientRTT := time.Since(t0).Microseconds()

		if err != nil {
			log.Fatalf("submission %d failed: %v", i, err)
		}

		sample := sampleResult{
			Index:       i,
			LeafIndex:   result.leafIndex,
			TreeSize:    result.treeSize,
			ClientRTTUS: clientRTT,
			ServerTiming: result.timing,
		}
		samples = append(samples, sample)

		if (i+1)%10 == 0 {
			fmt.Fprintf(os.Stderr, "  %d/%d (tree_size=%d, total=%dµs, rtt=%dµs)\n",
				i+1, cfg.N, result.treeSize, result.timing.TotalUS, clientRTT)
		}
	}

	endSize := getTreeSize(cfg.ATLURL)

	// Compute stats
	result := benchmarkResult{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		N:            cfg.N,
		Warmup:       cfg.Warmup,
		PayloadSize:  cfg.PayloadSize,
		LogSizeStart: startSize,
		LogSizeEnd:   endSize,
		Steps:        computeStepStats(samples),
		ClientRTT:    computeStats(extractField(samples, func(s sampleResult) float64 { return float64(s.ClientRTTUS) })),
		Samples:      samples,
	}

	out, _ := json.MarshalIndent(result, "", "  ")

	if cfg.Output != "" {
		os.MkdirAll(filepath.Dir(cfg.Output), 0755)
		if err := os.WriteFile(cfg.Output, out, 0644); err != nil {
			log.Fatalf("writing output: %v", err)
		}
		fmt.Fprintf(os.Stderr, "\nResults written to %s\n", cfg.Output)
	} else {
		fmt.Println(string(out))
	}

	// Print summary table (LaTeX-ready)
	printSummary(result)
}

type submitResult struct {
	leafIndex int64
	treeSize  uint64
	timing    serverTiming
}

func submitOne(atlURL, submitterID string, privKey ed25519.PrivateKey, payloadSize int, seqNum uint64) (*submitResult, error) {
	// Create realistic-sized entry
	attestation := make([]byte, payloadSize)
	rand.Read(attestation)
	nonce := make([]byte, 32)
	rand.Read(nonce)

	ha := entry.HAEntry{
		EntryType:   entry.EntryTypeHA,
		JobID:       fmt.Sprintf("BENCH-%012d", seqNum),
		TEEPlatform: "aws-nitro",
		Attestation: attestation,
		Nonce:       nonce,
		SubmitterID: submitterID,
	}

	body, err := entry.Marshal(ha)
	if err != nil {
		return nil, fmt.Errorf("marshal entry: %w", err)
	}

	// Sign with coordinator key (Ed25519 over body)
	sig := ed25519.Sign(privKey, body)

	req, err := http.NewRequest("POST", atlURL+"/v1/entries", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("X-Submitter-ID", submitterID)
	req.Header.Set("X-Coordinator-Signature", base64.StdEncoding.EncodeToString(sig))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse CBOR response
	var respMap map[interface{}]interface{}
	if err := cbor.Unmarshal(respBody, &respMap); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	result := &submitResult{
		leafIndex: toInt64(respMap["leaf_index"]),
		treeSize:  toUint64(respMap["tree_size"]),
	}

	if timingRaw, ok := respMap["timing"]; ok {
		if tm, ok := timingRaw.(map[interface{}]interface{}); ok {
			result.timing = serverTiming{
				AuthUS:       toInt64(tm["auth_us"]),
				PolicyUS:     toInt64(tm["policy_us"]),
				LeafHashUS:   toInt64(tm["leaf_hash_us"]),
				DedupCheckUS: toInt64(tm["dedup_check_us"]),
				DBInsertUS:   toInt64(tm["db_insert_us"]),
				TreeAppendUS: toInt64(tm["tree_append_us"]),
				STHSignUS:    toInt64(tm["sth_sign_us"]),
				StateSaveUS:  toInt64(tm["state_save_us"]),
				ReceiptGenUS: toInt64(tm["receipt_gen_us"]),
				TotalUS:      toInt64(tm["total_us"]),
			}
		}
	}

	return result, nil
}

func getTreeSize(atlURL string) uint64 {
	resp, err := http.Get(atlURL + "/v1/sth")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return 0 // empty log
	}
	body, _ := io.ReadAll(resp.Body)
	var m map[interface{}]interface{}
	if cbor.Unmarshal(body, &m) != nil {
		return 0
	}
	return toUint64(m["tree_size"])
}

func computeStepStats(samples []sampleResult) map[string]*stepStats {
	steps := map[string]func(sampleResult) float64{
		"auth":        func(s sampleResult) float64 { return float64(s.ServerTiming.AuthUS) },
		"policy":      func(s sampleResult) float64 { return float64(s.ServerTiming.PolicyUS) },
		"leaf_hash":   func(s sampleResult) float64 { return float64(s.ServerTiming.LeafHashUS) },
		"dedup_check": func(s sampleResult) float64 { return float64(s.ServerTiming.DedupCheckUS) },
		"db_insert":   func(s sampleResult) float64 { return float64(s.ServerTiming.DBInsertUS) },
		"tree_append": func(s sampleResult) float64 { return float64(s.ServerTiming.TreeAppendUS) },
		"sth_sign":    func(s sampleResult) float64 { return float64(s.ServerTiming.STHSignUS) },
		"state_save":  func(s sampleResult) float64 { return float64(s.ServerTiming.StateSaveUS) },
		"receipt_gen": func(s sampleResult) float64 { return float64(s.ServerTiming.ReceiptGenUS) },
		"total":       func(s sampleResult) float64 { return float64(s.ServerTiming.TotalUS) },
	}

	result := make(map[string]*stepStats)
	for name, extractor := range steps {
		vals := extractField(samples, extractor)
		result[name] = computeStats(vals)
	}
	return result
}

func extractField(samples []sampleResult, fn func(sampleResult) float64) []float64 {
	vals := make([]float64, len(samples))
	for i, s := range samples {
		vals[i] = fn(s)
	}
	return vals
}

func computeStats(vals []float64) *stepStats {
	if len(vals) == 0 {
		return &stepStats{}
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

	return &stepStats{
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
	if lower == upper {
		return sorted[lower]
	}
	frac := idx - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

func printSummary(r benchmarkResult) {
	fmt.Fprintf(os.Stderr, "\n=== TDSC Table 5: ATL Submission Latency Decomposition ===\n")
	fmt.Fprintf(os.Stderr, "N=%d | Log size: %d → %d | Payload: %d bytes\n\n",
		r.N, r.LogSizeStart, r.LogSizeEnd, r.PayloadSize)

	order := []struct{ name, label string }{
		{"auth", "Ed25519 verify (auth)"},
		{"policy", "Registration policy"},
		{"leaf_hash", "Leaf hash (SHA-256)"},
		{"dedup_check", "Dedup check (DB)"},
		{"db_insert", "DB INSERT"},
		{"tree_append", "Merkle tree append"},
		{"sth_sign", "STH sign (Ed25519)"},
		{"state_save", "Compact state persist"},
		{"receipt_gen", "Receipt (COSE_Sign1)"},
		{"total", "Total (server)"},
	}

	fmt.Fprintf(os.Stderr, "%-25s %10s %10s %10s %10s %10s\n",
		"Step", "Mean(µs)", "Std(µs)", "P50(µs)", "P95(µs)", "P99(µs)")
	fmt.Fprintf(os.Stderr, "%s\n", "------------------------------------------------------------------------------------")

	for _, o := range order {
		s := r.Steps[o.name]
		if s == nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "%-25s %10.1f %10.1f %10.1f %10.1f %10.1f\n",
			o.label, s.Mean, s.Std, s.P50, s.P95, s.P99)
	}

	fmt.Fprintf(os.Stderr, "%-25s %10.1f %10.1f %10.1f %10.1f %10.1f\n",
		"Client RTT", r.ClientRTT.Mean, r.ClientRTT.Std, r.ClientRTT.P50, r.ClientRTT.P95, r.ClientRTT.P99)

	// LaTeX snippet
	fmt.Fprintf(os.Stderr, "\n%% LaTeX table row format: Step & Mean & P50 & P95 \\\\\n")
	for _, o := range order {
		s := r.Steps[o.name]
		if s == nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "%s & %.0f & %.0f & %.0f \\\\\n", o.label, s.Mean, s.P50, s.P95)
	}
}

func toInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	case float64:
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
	case float64:
		return uint64(n)
	default:
		return 0
	}
}

func envOrFatal(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
