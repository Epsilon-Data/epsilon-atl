package policy

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

// Policy validates entries before they are accepted into the log.
// The ATL is TEE-agnostic: it accepts attestation documents from any
// supported TEE platform. Platform-specific verification is optional
// and pluggable via AttestationVerifier.
type Policy struct {
	allowedMeasurements map[string][]string                // platform → allowed measurement values
	freshnessWindow     int64                              // seconds
	coordinatorKeys     map[string]ed25519.PublicKey
	verifiers           map[string]AttestationVerifier      // platform → verifier (optional)
}

// Config holds policy configuration.
type Config struct {
	// AllowedPCR0 is a legacy field for Nitro PCR0 values.
	// Use AllowedMeasurements for multi-platform support.
	AllowedPCR0 []string

	// AllowedMeasurements maps TEE platform → allowed measurement values.
	// For Nitro: PCR0 hashes. For SGX: MRENCLAVE values. etc.
	// If empty for a platform, measurement checking is skipped.
	AllowedMeasurements map[string][]string

	FreshnessWindow int64 // seconds, default 86400 (24h)
	CoordinatorKeys map[string]ed25519.PublicKey

	// Verifiers maps TEE platform → attestation verifier.
	// Optional. When not set for a platform, structural validation only.
	Verifiers map[string]AttestationVerifier
}

// New creates a new Policy.
func New(cfg Config) *Policy {
	if cfg.FreshnessWindow == 0 {
		cfg.FreshnessWindow = 86400
	}

	measurements := cfg.AllowedMeasurements
	if measurements == nil {
		measurements = make(map[string][]string)
	}
	// Migrate legacy AllowedPCR0 to AllowedMeasurements
	if len(cfg.AllowedPCR0) > 0 && len(measurements["aws-nitro"]) == 0 {
		measurements["aws-nitro"] = cfg.AllowedPCR0
	}

	verifiers := cfg.Verifiers
	if verifiers == nil {
		verifiers = make(map[string]AttestationVerifier)
	}

	return &Policy{
		allowedMeasurements: measurements,
		freshnessWindow:     cfg.FreshnessWindow,
		coordinatorKeys:     cfg.CoordinatorKeys,
		verifiers:           verifiers,
	}
}

// Validate dispatches validation based on entry type.
func (p *Policy) Validate(entryType int, entryCBOR []byte) error {
	switch entryType {
	case entry.EntryTypeHA:
		return p.validateHA(entryCBOR)
	case entry.EntryTypeLA:
		return p.validateLA(entryCBOR)
	case entry.EntryTypeConfig:
		return p.validateConfig(entryCBOR)
	case entry.EntryTypeCommitment:
		return p.validateCommitment(entryCBOR)
	default:
		return fmt.Errorf("unknown entry type: %d", entryType)
	}
}
