package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Epsilon-Data/epsilon-atl/internal/api"
	"github.com/Epsilon-Data/epsilon-atl/internal/config"
	"github.com/Epsilon-Data/epsilon-atl/internal/merkle"
	"github.com/Epsilon-Data/epsilon-atl/internal/policy"
	"github.com/Epsilon-Data/epsilon-atl/internal/receipt"
	"github.com/Epsilon-Data/epsilon-atl/internal/sth"
	"github.com/Epsilon-Data/epsilon-atl/internal/store"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "atl",
		Short: "Attestation Transparency Log",
	}

	rootCmd.AddCommand(serveCmd())
	rootCmd.AddCommand(keygenCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the ATL HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Open database
			s, err := store.New(cfg.DatabaseURL)
			if err != nil {
				return fmt.Errorf("connecting to database: %w", err)
			}
			defer s.Close()

			if err := s.EnsureSchema(); err != nil {
				return fmt.Errorf("ensuring schema: %w", err)
			}

			// Load operator key
			operatorPriv, err := sth.LoadPrivateKey(cfg.OperatorKeyPath)
			if err != nil {
				return fmt.Errorf("loading operator key: %w", err)
			}
			operatorPub := operatorPriv.Public().(ed25519.PublicKey)
			operatorPubBytes, _ := x509.MarshalPKIXPublicKey(operatorPub)

			// Initialize tree
			tree := merkle.NewTree()

			// Rebuild tree from leaf hashes in database.
			// This populates the in-memory node cache needed for proof generation.
			// Compact state (size + O(log n) hashes) is persisted, but the full
			// node map (~2n entries) is rebuilt on startup to avoid storing a
			// multi-GB blob in the tree_state table.
			dbSize, err := s.TreeSize()
			if err != nil {
				return fmt.Errorf("checking tree size: %w", err)
			}
			if dbSize > 0 {
				log.Printf("Rebuilding tree from %d entries...", dbSize)
				start := time.Now()
				if err := tree.RebuildNodeCache(s.IterateLeafHashes); err != nil {
					return fmt.Errorf("rebuilding tree: %w", err)
				}
				log.Printf("Tree rebuilt: %d entries in %v", tree.Size(), time.Since(start))
			}

			// Create signer
			signer := sth.NewSigner(operatorPriv)

			// Create receipt generator
			receiptGen, err := receipt.NewGenerator(operatorPriv)
			if err != nil {
				return fmt.Errorf("creating receipt generator: %w", err)
			}

			// Create policy
			pol := policy.New(policy.Config{
				AllowedPCR0: cfg.AllowedPCR0,
			})

			// Load coordinator public keys from directory
			// Each file: {submitter_id}.pub (PEM-encoded Ed25519 public key)
			coordKeys := make(map[string]ed25519.PublicKey)
			if cfg.CoordinatorKeysDir != "" {
				entries, err := os.ReadDir(cfg.CoordinatorKeysDir)
				if err != nil {
					return fmt.Errorf("reading coordinator keys dir: %w", err)
				}
				for _, e := range entries {
					if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
						continue
					}
					submitterID := strings.TrimSuffix(e.Name(), ".pub")
					pemData, err := os.ReadFile(filepath.Join(cfg.CoordinatorKeysDir, e.Name()))
					if err != nil {
						return fmt.Errorf("reading coordinator key %s: %w", e.Name(), err)
					}
					block, _ := pem.Decode(pemData)
					if block == nil {
						return fmt.Errorf("invalid PEM in %s", e.Name())
					}
					pub, err := x509.ParsePKIXPublicKey(block.Bytes)
					if err != nil {
						return fmt.Errorf("parsing public key %s: %w", e.Name(), err)
					}
					edPub, ok := pub.(ed25519.PublicKey)
					if !ok {
						return fmt.Errorf("key %s is not Ed25519", e.Name())
					}
					coordKeys[submitterID] = edPub
					log.Printf("Loaded coordinator key: %s", submitterID)
				}
			}

			// Create server
			srv := api.NewServer(api.ServerConfig{
				Store:               s,
				Tree:                tree,
				Signer:              signer,
				Policy:              pol,
				ReceiptGen:          receiptGen,
				CoordinatorKeys:     coordKeys,
				AllowedSubmitters:   cfg.AllowedSubmitters,
				OperatorPubKeyBytes: operatorPubBytes,
				MMDSeconds:          cfg.MMDSeconds,
				Port:                cfg.Port,
			})

			// Start heartbeat
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			heartbeat := sth.NewHeartbeat(signer, tree, s, time.Duration(cfg.MMDSeconds)*time.Second)
			go heartbeat.Start(ctx)

			// Handle signals
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				<-sigCh
				log.Println("Shutting down...")
				cancel()
			}()

			return srv.StartWithGracefulShutdown(ctx)
		},
	}
}

func keygenCmd() *cobra.Command {
	var outputDir string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate Ed25519 operator keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				return fmt.Errorf("generating key: %w", err)
			}

			privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				return fmt.Errorf("marshaling private key: %w", err)
			}
			privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

			pubBytes, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				return fmt.Errorf("marshaling public key: %w", err)
			}
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

			privPath := outputDir + "/operator.key"
			pubPath := outputDir + "/operator.pub"

			if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
				return fmt.Errorf("writing private key: %w", err)
			}
			if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
				return fmt.Errorf("writing public key: %w", err)
			}

			fmt.Printf("Private key: %s\n", privPath)
			fmt.Printf("Public key:  %s\n", pubPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", ".", "Output directory for keypair")
	return cmd
}
