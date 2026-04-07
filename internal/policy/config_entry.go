package policy

import (
	"fmt"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

var validEvents = map[string]bool{
	"key_creation":   true,
	"key_rotation":   true,
	"key_revocation": true,
}

func (p *Policy) validateConfig(entryCBOR []byte) error {
	var e entry.ConfigEntry
	if err := entry.Unmarshal(entryCBOR, &e); err != nil {
		return fmt.Errorf("decoding config entry: %w", err)
	}

	if e.EntryType != entry.EntryTypeConfig {
		return fmt.Errorf("entry type mismatch: expected %d, got %d", entry.EntryTypeConfig, e.EntryType)
	}
	if !validEvents[e.Event] {
		return fmt.Errorf("invalid config event: %s", e.Event)
	}
	if len(e.SubjectKey) == 0 {
		return fmt.Errorf("config entry missing subject_key")
	}
	if e.SubmitterID == "" {
		return fmt.Errorf("config entry missing submitter_id")
	}

	// For rotation, predecessor key must sign
	if e.Event == "key_rotation" && len(e.Predecessor) == 0 {
		return fmt.Errorf("key_rotation requires predecessor signature")
	}

	return nil
}
