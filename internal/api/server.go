package api

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Epsilon-Data/epsilon-atl/internal/merkle"
	"github.com/Epsilon-Data/epsilon-atl/internal/sth"
	"github.com/Epsilon-Data/epsilon-atl/internal/store"
)

// ReceiptGenerator generates SCITT inclusion receipts.
type ReceiptGenerator interface {
	Generate(leafIndex, treeSize uint64, rootHash []byte, inclusionPath [][]byte) ([]byte, error)
}

// PolicyValidator validates entries against registration policy.
type PolicyValidator interface {
	Validate(entryType int, entryCBOR []byte) error
}

// Server is the ATL HTTP server.
type Server struct {
	store              *store.Store
	tree               *merkle.Tree
	signer             *sth.Signer
	policy             PolicyValidator
	receiptGen         ReceiptGenerator
	coordinatorKeys    map[string]ed25519.PublicKey
	allowedSubmitters  []string
	operatorPubKeyBytes []byte
	mmdSeconds         int
	httpServer         *http.Server
}

// ServerConfig holds configuration for creating a new Server.
type ServerConfig struct {
	Store              *store.Store
	Tree               *merkle.Tree
	Signer             *sth.Signer
	Policy             PolicyValidator
	ReceiptGen         ReceiptGenerator
	CoordinatorKeys    map[string]ed25519.PublicKey
	AllowedSubmitters  []string
	OperatorPubKeyBytes []byte
	MMDSeconds         int
	Port               int
}

// NewServer creates a new ATL HTTP server.
func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		store:              cfg.Store,
		tree:               cfg.Tree,
		signer:             cfg.Signer,
		policy:             cfg.Policy,
		receiptGen:         cfg.ReceiptGen,
		coordinatorKeys:    cfg.CoordinatorKeys,
		allowedSubmitters:  cfg.AllowedSubmitters,
		operatorPubKeyBytes: cfg.OperatorPubKeyBytes,
		mmdSeconds:         cfg.MMDSeconds,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/entries", s.handleSubmitEntry)
	mux.HandleFunc("GET /v1/entries/{index}", s.handleGetEntry)
	mux.HandleFunc("GET /v1/entries/{index}/proof", s.handleInclusionProof)
	mux.HandleFunc("GET /v1/sth", s.handleGetSTH)
	mux.HandleFunc("GET /v1/sth/consistency", s.handleConsistencyProof)
	mux.HandleFunc("GET /v1/metadata", s.handleMetadata)
	mux.HandleFunc("GET /health", s.handleHealth)

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: mux,
	}
	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	log.Printf("ATL server listening on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Serve starts the HTTP server on the given listener.
func (s *Server) Serve(ln net.Listener) error {
	return s.httpServer.Serve(ln)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the HTTP handler for testing.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}


// StartWithGracefulShutdown starts the server and handles context cancellation.
func (s *Server) StartWithGracefulShutdown(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
