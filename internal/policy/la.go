package policy

import (
	"fmt"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

func (p *Policy) validateLA(entryCBOR []byte) error {
	var e entry.LAEntry
	if err := entry.Unmarshal(entryCBOR, &e); err != nil {
		return fmt.Errorf("decoding LA entry: %w", err)
	}

	if e.EntryType != entry.EntryTypeLA {
		return fmt.Errorf("entry type mismatch: expected %d, got %d", entry.EntryTypeLA, e.EntryType)
	}
	if e.ErrorClass == "" {
		return fmt.Errorf("LA entry missing error_class")
	}
	if e.SubmitterID == "" {
		return fmt.Errorf("LA entry missing submitter_id")
	}

	// Coordinator signature verification is handled at the API auth layer.
	// Policy only validates structure.

	return nil
}
