package policy

import (
	"fmt"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

// commitmentHashLen is the expected SHA-256 commitment hash length in bytes.
const commitmentHashLen = 32

func (p *Policy) validateCommitment(entryCBOR []byte) error {
	var e entry.CommitmentEntry
	if err := entry.Unmarshal(entryCBOR, &e); err != nil {
		return fmt.Errorf("decoding commitment entry: %w", err)
	}

	if e.EntryType != entry.EntryTypeCommitment {
		return fmt.Errorf("entry type mismatch: expected %d, got %d", entry.EntryTypeCommitment, e.EntryType)
	}
	if e.JobID == "" {
		return fmt.Errorf("commitment entry missing job_id")
	}
	if len(e.CommitmentHash) != commitmentHashLen {
		return fmt.Errorf("commitment hash must be %d bytes (SHA-256), got %d", commitmentHashLen, len(e.CommitmentHash))
	}
	if len(e.CoordSignature) == 0 {
		return fmt.Errorf("commitment entry missing coordinator signature")
	}
	if e.SubmitterID == "" {
		return fmt.Errorf("commitment entry missing submitter_id")
	}

	// Coordinator signature verification is handled at the API auth layer
	// (parallel to LA entries). Policy only validates structure.

	return nil
}
