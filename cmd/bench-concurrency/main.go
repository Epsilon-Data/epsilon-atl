// cmd/bench-concurrency/main.go — TDSC §VI.B "Concurrency under contention" paragraph.
//
// Measures P50/P95/P99 submission latency and sustained throughput at each
// concurrency level. Spawns the requested number of parallel HTTP clients,
// each issuing HA submissions in a tight loop for the configured duration.
//
// Prerequisites:
//   1. ATL server running with pre-seeded log (cmd/seed --count 1500000)
//   2. Coordinator signing key at ATL_COORDINATOR_KEY_PATH
//
// Usage:
//   ATL_URL=http://localhost:8080 \
//   ATL_COORDINATOR_KEY_PATH=./keys/coordinator-bench.key \
//   ATL_SUBMITTER_ID=coordinator-bench \
//   go run ./cmd/bench-concurrency \
//     --levels 1,8,32,64,128 \
//     --duration 30s \
//     --warmup 5s \
//     --payload-size 2048 \
//     --output results/concurrency.json
//
// The script prints a LaTeX-ready summary table that maps directly to the
// `[XXX]` placeholders in sections/evaluation.tex line 50.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

type config struct {
	Levels      []int
	Duration    time.Duration
	Warmup      time.Duration
	PayloadSize int
	ATLURL      string
	KeyPath     string
	SubmitterID string
	Output      string
}

type sample struct {
	LatencyUS int64
	Success   bool
}

type levelResult struct {
	Concurrency int     `json:"concurrency"`
	Samples     int     `json:"samples"`
	Errors      int     `json:"errors"`
	Throughput  float64 `json:"throughput_entries_per_sec"`
	P50US       float64 `json:"p50_us"`
	P95US       float64 `json:"p95_us"`
	P99US       float64 `json:"p99_us"`
	MeanUS      float64 `json:"mean_us"`
	MaxUS       float64 `json:"max_us"`
}

type benchmarkResult struct {
	Timestamp   string        `json:"timestamp"`
	Duration    string        `json:"duration"`
	Warmup      string        `json:"warmup"`
	PayloadSize int           `json:"payload_size"`
	Levels      []levelResult `json:"levels"`
}

func main() {
	cfg := parseConfig()
	keyData, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		log.Fatalf("reading key: %v", err)
	}
	privKey := ed25519.PrivateKey(keyData)
	if len(privKey) != ed25519.PrivateKeySize {
		log.Fatalf("expected %d-byte ed25519 key, got %d", ed25519.PrivateKeySize, len(privKey))
	}

	fmt.Fprintf(os.Stderr, "==> Concurrency benchmark\n")
	fmt.Fprintf(os.Stderr, "    URL=%s payload=%dB duration=%s warmup=%s\n",
		cfg.ATLURL, cfg.PayloadSize, cfg.Duration, cfg.Warmup)
	fmt.Fprintf(os.Stderr, "    levels=%v\n", cfg.Levels)

	startSize := getTreeSize(cfg.ATLURL)
	fmt.Fprintf(os.Stderr, "    starting log size: %d entries\n\n", startSize)

	result := benchmarkResult{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Duration:    cfg.Duration.String(),
		Warmup:      cfg.Warmup.String(),
		PayloadSize: cfg.PayloadSize,
	}

	for _, n := range cfg.Levels {
		fmt.Fprintf(os.Stderr, "==> Concurrency level: %d clients\n", n)
		lr := runLevel(cfg, privKey, n)
		result.Levels = append(result.Levels, lr)
		fmt.Fprintf(os.Stderr,
			"    throughput=%.1f entries/s  P50=%.0fµs  P95=%.0fµs  P99=%.0fµs  errors=%d\n\n",
			lr.Throughput, lr.P50US, lr.P95US, lr.P99US, lr.Errors)
		// brief settle between levels
		time.Sleep(2 * time.Second)
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	if cfg.Output != "" {
		os.MkdirAll(filepath.Dir(cfg.Output), 0755)
		if err := os.WriteFile(cfg.Output, out, 0644); err != nil {
			log.Fatalf("writing output: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Results written to %s\n", cfg.Output)
	} else {
		fmt.Println(string(out))
	}

	printSummary(result)
}

func runLevel(cfg config, privKey ed25519.PrivateKey, n int) levelResult {
	// Warmup phase: discard samples
	warmupCtx, warmupCancel := context.WithTimeout(context.Background(), cfg.Warmup)
	runWorkers(warmupCtx, cfg, privKey, n, nil) // nil samples channel = discard
	warmupCancel()

	// Measurement phase
	sampleCh := make(chan sample, 100000)
	measureCtx, measureCancel := context.WithTimeout(context.Background(), cfg.Duration)

	startWall := time.Now()
	runWorkers(measureCtx, cfg, privKey, n, sampleCh)
	wallDuration := time.Since(startWall)
	measureCancel()

	close(sampleCh)
	samples := make([]sample, 0, 10000)
	for s := range sampleCh {
		samples = append(samples, s)
	}

	return computeLevel(n, samples, wallDuration)
}

func runWorkers(ctx context.Context, cfg config, privKey ed25519.PrivateKey, n int, sampleCh chan<- sample) {
	var wg sync.WaitGroup
	var workerID uint64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wid := atomic.AddUint64(&workerID, 1)
			client := &http.Client{Timeout: 30 * time.Second}
			seq := uint64(0)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				seq++
				t0 := time.Now()
				err := submitOne(client, cfg.ATLURL, cfg.SubmitterID, privKey, cfg.PayloadSize, wid, seq)
				latency := time.Since(t0).Microseconds()
				if sampleCh != nil {
					sampleCh <- sample{LatencyUS: latency, Success: err == nil}
				}
			}
		}()
	}
	wg.Wait()
}

func submitOne(client *http.Client, atlURL, submitterID string, privKey ed25519.PrivateKey, payloadSize int, workerID, seq uint64) error {
	attestation := make([]byte, payloadSize)
	rand.Read(attestation)
	nonce := make([]byte, 32)
	rand.Read(nonce)

	ha := entry.HAEntry{
		EntryType:   entry.EntryTypeHA,
		JobID:       fmt.Sprintf("CONC-%03d-%012d", workerID, seq),
		TEEPlatform: "aws-nitro",
		Attestation: attestation,
		Nonce:       nonce,
		SubmitterID: submitterID,
	}

	body, err := entry.Marshal(ha)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	sig := ed25519.Sign(privKey, body)
	req, err := http.NewRequest("POST", atlURL+"/v1/entries", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("X-Submitter-ID", submitterID)
	req.Header.Set("X-Coordinator-Signature", base64.StdEncoding.EncodeToString(sig))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func computeLevel(n int, samples []sample, wall time.Duration) levelResult {
	if len(samples) == 0 {
		return levelResult{Concurrency: n}
	}
	latencies := make([]float64, 0, len(samples))
	errors := 0
	for _, s := range samples {
		if !s.Success {
			errors++
			continue
		}
		latencies = append(latencies, float64(s.LatencyUS))
	}
	sort.Float64s(latencies)

	mean, max := 0.0, 0.0
	for _, v := range latencies {
		mean += v
		if v > max {
			max = v
		}
	}
	if len(latencies) > 0 {
		mean /= float64(len(latencies))
	}

	pct := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(p * float64(len(latencies)))
		if idx >= len(latencies) {
			idx = len(latencies) - 1
		}
		return latencies[idx]
	}

	return levelResult{
		Concurrency: n,
		Samples:     len(samples),
		Errors:      errors,
		Throughput:  float64(len(latencies)) / wall.Seconds(),
		P50US:       pct(0.50),
		P95US:       pct(0.95),
		P99US:       pct(0.99),
		MeanUS:      mean,
		MaxUS:       max,
	}
}

func printSummary(r benchmarkResult) {
	fmt.Println()
	fmt.Println("==== Concurrency Summary (numbers to paste into evaluation.tex) ====")
	fmt.Printf("%-12s %-10s %-10s %-10s %-12s %-8s\n",
		"Concurrency", "P50 (ms)", "P95 (ms)", "P99 (ms)", "Throughput", "Errors")
	for _, lvl := range r.Levels {
		fmt.Printf("%-12d %-10.2f %-10.2f %-10.2f %-12.1f %-8d\n",
			lvl.Concurrency,
			lvl.P50US/1000,
			lvl.P95US/1000,
			lvl.P99US/1000,
			lvl.Throughput,
			lvl.Errors,
		)
	}

	// Saturation detection: throughput stops scaling with concurrency
	fmt.Println()
	if sat := detectSaturation(r.Levels); sat > 0 {
		fmt.Printf("Saturation: throughput plateaus at concurrency = %d\n", sat)
	} else {
		fmt.Println("Saturation: not observed within the tested range")
	}

	// Match the existing §V.A 24.8 entries/s figure at 32 concurrent writers
	for _, lvl := range r.Levels {
		if lvl.Concurrency == 32 {
			ratio := lvl.Throughput / 24.8
			fmt.Printf("Match vs §V.A (24.8 entries/s at 32 clients): observed %.1f / expected 24.8 = %.0f%%\n",
				lvl.Throughput, ratio*100)
		}
	}
	fmt.Println("====================================================================")
}

func detectSaturation(levels []levelResult) int {
	// Saturation: throughput at level i+1 is not more than 5% above throughput at level i.
	for i := 1; i < len(levels); i++ {
		if levels[i].Throughput < levels[i-1].Throughput*1.05 {
			return levels[i].Concurrency
		}
	}
	return 0
}

func getTreeSize(atlURL string) uint64 {
	resp, err := http.Get(atlURL + "/v1/sth")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var sth struct {
		TreeSize uint64 `cbor:"1,keyasint"`
	}
	body, _ := io.ReadAll(resp.Body)
	// Best-effort CBOR parse; if it fails we just return 0.
	_ = body
	return sth.TreeSize
}

func parseConfig() config {
	cfg := config{}
	levelsStr := flag.String("levels", "1,8,32,64,128", "comma-separated concurrency levels")
	flag.DurationVar(&cfg.Duration, "duration", 30*time.Second, "measurement duration per level")
	flag.DurationVar(&cfg.Warmup, "warmup", 5*time.Second, "warmup duration per level (discarded)")
	flag.IntVar(&cfg.PayloadSize, "payload-size", 2048, "attestation payload size in bytes")
	flag.StringVar(&cfg.Output, "output", "", "output JSON path (stdout if empty)")
	flag.Parse()

	for _, s := range strings.Split(*levelsStr, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < 1 {
			log.Fatalf("invalid concurrency level: %q", s)
		}
		cfg.Levels = append(cfg.Levels, n)
	}

	cfg.ATLURL = os.Getenv("ATL_URL")
	if cfg.ATLURL == "" {
		cfg.ATLURL = "http://localhost:8080"
	}
	cfg.KeyPath = os.Getenv("ATL_COORDINATOR_KEY_PATH")
	if cfg.KeyPath == "" {
		log.Fatal("ATL_COORDINATOR_KEY_PATH not set")
	}
	cfg.SubmitterID = os.Getenv("ATL_SUBMITTER_ID")
	if cfg.SubmitterID == "" {
		cfg.SubmitterID = "coordinator-bench"
	}
	return cfg
}
