package policy

import (
	"crypto/ed25519"
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

	// Verify the in-entry coordinator signature so the entry is auditable
	// offline from the log archive alone, without trusting the log operator's
	// HTTP auth layer. Signed payload is (job_id || commitment_hash); pubkey
	// is looked up by submitter_id in the configured coordinator key set.
	pubkey, ok := p.coordinatorKeys[e.SubmitterID]
	if !ok {
		return fmt.Errorf("unknown submitter_id: %s", e.SubmitterID)
	}
	signed := append([]byte(e.JobID), e.CommitmentHash...)
	if !ed25519.Verify(pubkey, signed, e.CoordSignature) {
		return fmt.Errorf("invalid coordinator signature over (job_id || commitment_hash)")
	}

	return nil
}