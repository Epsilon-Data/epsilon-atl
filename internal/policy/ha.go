package policy

import (
	"fmt"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

func (p *Policy) validateHA(entryCBOR []byte) error {
	var e entry.HAEntry
	if err := entry.Unmarshal(entryCBOR, &e); err != nil {
		return fmt.Errorf("decoding HA entry: %w", err)
	}

	if e.EntryType != entry.EntryTypeHA {
		return fmt.Errorf("entry type mismatch: expected %d, got %d", entry.EntryTypeHA, e.EntryType)
	}
	if e.JobID == "" {
		return fmt.Errorf("HA entry missing job_id")
	}
	if e.TEEPlatform == "" {
		return fmt.Errorf("HA entry missing tee_platform")
	}
	if len(e.Attestation) == 0 {
		return fmt.Errorf("HA entry missing attestation")
	}
	if e.SubmitterID == "" {
		return fmt.Errorf("HA entry missing submitter_id")
	}

	// TEE platform validation — accept any registered platform
	if !IsSupportedPlatform(e.TEEPlatform) {
		return fmt.Errorf("unsupported TEE platform: %s (supported: aws-nitro, intel-sgx, intel-tdx, amd-sev-snp, arm-cca)", e.TEEPlatform)
	}

	// Platform-specific attestation verification (optional, pluggable).
	// When a verifier is registered for this platform, run it.
	// When no verifier is registered, accept based on structural validation.
	// The submitting coordinator is responsible for attestation appraisal
	// before forwarding to the ATL.
	if verifier, ok := p.verifiers[e.TEEPlatform]; ok {
		if err := verifier.Verify(e.Attestation, p.allowedMeasurements[e.TEEPlatform]); err != nil {
			return fmt.Errorf("attestation verification failed (%s): %w", e.TEEPlatform, err)
		}
	}

	return nil
}
