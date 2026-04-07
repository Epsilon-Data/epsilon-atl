package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
	"github.com/Epsilon-Data/epsilon-atl/internal/merkle"
	"github.com/Epsilon-Data/epsilon-atl/internal/sth"
	"github.com/Epsilon-Data/epsilon-atl/internal/store"
)

func main() {
	count := flag.Int("count", 0, "Number of synthetic HA entries to bulk-seed (0 = use default sample data)")
	flag.Parse()

	dbURL := os.Getenv("ATL_DATABASE_URL")
	if dbURL == "" {
		log.Fatal("ATL_DATABASE_URL required")
	}
	keyPath := os.Getenv("ATL_OPERATOR_KEY_PATH")
	if keyPath == "" {
		keyPath = "/tmp/atl-test/operator.key"
	}

	s, err := store.New(dbURL)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer s.Close()
	if err := s.EnsureSchema(); err != nil {
		log.Fatalf("schema: %v", err)
	}

	privKey, err := sth.LoadPrivateKey(keyPath)
	if err != nil {
		log.Fatalf("key: %v", err)
	}
	signer := sth.NewSigner(privKey)
	tree := merkle.NewTree()

	// Restore existing tree by rebuilding from leaf hashes
	dbSize, err := s.TreeSize()
	if err != nil {
		log.Fatalf("tree size: %v", err)
	}
	if dbSize > 0 {
		fmt.Printf("Rebuilding tree from %d entries...\n", dbSize)
		if err := tree.RebuildNodeCache(s.IterateLeafHashes); err != nil {
			log.Fatalf("rebuild tree: %v", err)
		}
		fmt.Printf("Restored tree: size=%d\n", tree.Size())
	}

	appendEntry := func(typ int, raw interface{}, jobID, platform, submitter string) {
		data, _ := entry.Marshal(raw)
		leafHash := merkle.HashLeaf(data)
		idx, err := s.AppendEntry(typ, data, leafHash, jobID, platform, submitter)
		if err != nil {
			log.Printf("  skip: %v", err)
			return
		}
		tree.Append(leafHash)
		fmt.Printf("  #%d %s\n", idx, jobID)
	}

	if *count > 0 {
		// Bulk seeding mode for benchmarks
		fmt.Printf("Bulk seeding %d HA entries...\n", *count)
		batchSize := 1000
		for i := 0; i < *count; i++ {
			jobID := fmt.Sprintf("BENCH-%08d", int(tree.Size())+1)
			nonce := make([]byte, 32)
			rand.Read(nonce)
			attestation := make([]byte, 64)
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
			idx, err := s.AppendEntry(entry.EntryTypeHA, data, leafHash, jobID, "aws-nitro", "coordinator-bench")
			if err != nil {
				log.Printf("  skip %s: %v", jobID, err)
				continue
			}
			tree.Append(leafHash)

			if (i+1)%batchSize == 0 || i == *count-1 {
				fmt.Printf("  seeded %d/%d (latest: #%d %s)\n", i+1, *count, idx, jobID)
			}
		}
	} else {
		// Default sample data mode
		fmt.Println("Seeding HA entries...")
		for i, job := range []string{"JOB-A1B2C", "JOB-D3E4F", "JOB-G5H6I", "JOB-J7K8L", "JOB-M9N0P", "JOB-Q1R2S", "JOB-T3U4V"} {
			coord := "coord-prod-1"
			if i >= 5 {
				coord = "coord-prod-2"
			}
			appendEntry(entry.EntryTypeHA, entry.HAEntry{
				EntryType:   entry.EntryTypeHA,
				JobID:       job,
				TEEPlatform: "aws-nitro",
				Attestation: []byte{0xd2, 0x84, byte(i)},
				Nonce:       []byte{byte(i + 1)},
				SubmitterID: coord,
			}, job, "aws-nitro", coord)
		}

		fmt.Println("Seeding LA entries...")
		appendEntry(entry.EntryTypeLA, entry.LAEntry{
			EntryType: entry.EntryTypeLA, JobID: "JOB-W5X6Y",
			ErrorClass: "timeout", ErrorDetail: "enclave did not respond within 30s",
			SubmitterID: "coord-prod-1",
		}, "JOB-W5X6Y", "", "coord-prod-1")

		appendEntry(entry.EntryTypeLA, entry.LAEntry{
			EntryType: entry.EntryTypeLA, JobID: "JOB-Z7A8B",
			ErrorClass: "crash", ErrorDetail: "segfault in user code",
			SubmitterID: "coord-prod-1",
		}, "JOB-Z7A8B", "", "coord-prod-1")

		fmt.Println("Seeding Config entry...")
		pubKey := privKey.Public().(ed25519.PublicKey)
		appendEntry(entry.EntryTypeConfig, entry.ConfigEntry{
			EntryType:   entry.EntryTypeConfig,
			Event:       "key_creation",
			SubjectKey:  []byte(pubKey),
			SubmitterID: "admin",
			Timestamp:   1742000000,
		}, "", "", "admin")
	}

	// Sign and save STH
	root, _ := tree.RootHash()
	if root == nil {
		log.Fatal("no entries were appended")
	}
	sthVal, err := signer.Sign(tree.Size(), root)
	if err != nil {
		log.Fatalf("sign STH: %v", err)
	}
	if err := s.SaveSTH(sthVal); err != nil {
		log.Fatalf("save STH: %v", err)
	}

	// Save tree state (compact hashes only — nodes rebuilt on startup)
	size, hashes := tree.CompactState()
	s.SaveTreeState(size, hashes, nil)

	fmt.Printf("\nDone! tree_size=%d root_hash=%x...\n", sthVal.TreeSize, sthVal.RootHash[:8])
}
