package sth

import (
	"context"
	"log"
	"time"
)

// TreeStateProvider supplies the current tree state for STH signing.
type TreeStateProvider interface {
	RootHash() ([]byte, error)
	Size() uint64
}

// STHPersister saves signed tree heads.
type STHPersister interface {
	SaveSTH(sth *SignedTreeHead) error
}

// Heartbeat periodically signs and persists STHs at the MMD interval.
type Heartbeat struct {
	signer   *Signer
	tree     TreeStateProvider
	store    STHPersister
	interval time.Duration
}

// NewHeartbeat creates a new heartbeat.
func NewHeartbeat(signer *Signer, tree TreeStateProvider, store STHPersister, interval time.Duration) *Heartbeat {
	return &Heartbeat{
		signer:   signer,
		tree:     tree,
		store:    store,
		interval: interval,
	}
}

// Start begins the heartbeat loop. It blocks until the context is cancelled.
func (h *Heartbeat) Start(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.beat(); err != nil {
				log.Printf("heartbeat STH error: %v", err)
			}
		}
	}
}

func (h *Heartbeat) beat() error {
	root, err := h.tree.RootHash()
	if err != nil {
		return err
	}
	if root == nil {
		// Empty tree — sign with zero hash
		root = make([]byte, 32)
	}
	sth, err := h.signer.Sign(h.tree.Size(), root)
	if err != nil {
		return err
	}
	return h.store.SaveSTH(sth)
}
