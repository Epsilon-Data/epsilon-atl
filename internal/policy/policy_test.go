package policy

import (
	"testing"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

func newTestPolicy() *Policy {
	return New(Config{
		AllowedPCR0:     []string{"abc123"},
		FreshnessWindow: 86400,
	})
}

func TestValidHA(t *testing.T) {
	p := newTestPolicy()
	e := entry.HAEntry{
		EntryType:   entry.EntryTypeHA,
		JobID:       "job-1",
		TEEPlatform: "aws-nitro",
		Attestation: []byte{0x01},
		Nonce:       []byte{0x02},
		SubmitterID: "coord-1",
	}
	data, _ := entry.Marshal(e)
	if err := p.Validate(entry.EntryTypeHA, data); err != nil {
		t.Fatalf("valid HA rejected: %v", err)
	}
}

func TestHAMissingFields(t *testing.T) {
	p := newTestPolicy()
	tests := []struct {
		name string
		e    entry.HAEntry
	}{
		{"missing job_id", entry.HAEntry{EntryType: entry.EntryTypeHA, TEEPlatform: "aws-nitro", Attestation: []byte{1}, SubmitterID: "c"}},
		{"missing platform", entry.HAEntry{EntryType: entry.EntryTypeHA, JobID: "j", Attestation: []byte{1}, SubmitterID: "c"}},
		{"missing attestation", entry.HAEntry{EntryType: entry.EntryTypeHA, JobID: "j", TEEPlatform: "aws-nitro", SubmitterID: "c"}},
		{"missing submitter", entry.HAEntry{EntryType: entry.EntryTypeHA, JobID: "j", TEEPlatform: "aws-nitro", Attestation: []byte{1}}},
	}
	for _, tc := range tests {
		data, _ := entry.Marshal(tc.e)
		if err := p.Validate(entry.EntryTypeHA, data); err == nil {
			t.Fatalf("%s: expected rejection", tc.name)
		}
	}
}

func TestHAUnknownPlatform(t *testing.T) {
	p := newTestPolicy()
	e := entry.HAEntry{
		EntryType:   entry.EntryTypeHA,
		JobID:       "j",
		TEEPlatform: "unknown-tee",
		Attestation: []byte{1},
		SubmitterID: "c",
	}
	data, _ := entry.Marshal(e)
	if err := p.Validate(entry.EntryTypeHA, data); err == nil {
		t.Fatal("expected rejection for unknown platform")
	}
}

func TestHAAllSupportedPlatforms(t *testing.T) {
	p := newTestPolicy()
	for platform := range SupportedPlatforms {
		e := entry.HAEntry{
			EntryType:   entry.EntryTypeHA,
			JobID:       "job-" + platform,
			TEEPlatform: platform,
			Attestation: []byte{0x01, 0x02, 0x03},
			Nonce:       []byte{0x04},
			SubmitterID: "coord-1",
		}
		data, _ := entry.Marshal(e)
		if err := p.Validate(entry.EntryTypeHA, data); err != nil {
			t.Fatalf("platform %s rejected: %v", platform, err)
		}
	}
}

func TestValidLA(t *testing.T) {
	p := newTestPolicy()
	e := entry.LAEntry{
		EntryType:   entry.EntryTypeLA,
		JobID:       "job-2",
		ErrorClass:  "timeout",
		ErrorDetail: "enclave unreachable",
		SubmitterID: "coord-1",
	}
	data, _ := entry.Marshal(e)
	if err := p.Validate(entry.EntryTypeLA, data); err != nil {
		t.Fatalf("valid LA rejected: %v", err)
	}
}

func TestLAMissingErrorClass(t *testing.T) {
	p := newTestPolicy()
	e := entry.LAEntry{
		EntryType:   entry.EntryTypeLA,
		JobID:       "j",
		SubmitterID: "c",
	}
	data, _ := entry.Marshal(e)
	if err := p.Validate(entry.EntryTypeLA, data); err == nil {
		t.Fatal("expected rejection for missing error_class")
	}
}

func TestValidConfig(t *testing.T) {
	p := newTestPolicy()
	e := entry.ConfigEntry{
		EntryType:   entry.EntryTypeConfig,
		Event:       "key_creation",
		SubjectKey:  []byte{0xAA},
		SubmitterID: "admin",
		Timestamp:   1700000000,
	}
	data, _ := entry.Marshal(e)
	if err := p.Validate(entry.EntryTypeConfig, data); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestConfigInvalidEvent(t *testing.T) {
	p := newTestPolicy()
	e := entry.ConfigEntry{
		EntryType:   entry.EntryTypeConfig,
		Event:       "key_deletion",
		SubjectKey:  []byte{0xAA},
		SubmitterID: "admin",
		Timestamp:   1700000000,
	}
	data, _ := entry.Marshal(e)
	if err := p.Validate(entry.EntryTypeConfig, data); err == nil {
		t.Fatal("expected rejection for invalid event")
	}
}

func TestConfigRotationRequiresPredecessor(t *testing.T) {
	p := newTestPolicy()
	e := entry.ConfigEntry{
		EntryType:   entry.EntryTypeConfig,
		Event:       "key_rotation",
		SubjectKey:  []byte{0xAA},
		SubmitterID: "admin",
		Timestamp:   1700000000,
	}
	data, _ := entry.Marshal(e)
	if err := p.Validate(entry.EntryTypeConfig, data); err == nil {
		t.Fatal("expected rejection for rotation without predecessor")
	}
}

func TestUnknownEntryType(t *testing.T) {
	p := newTestPolicy()
	if err := p.Validate(99, []byte{0x01}); err == nil {
		t.Fatal("expected rejection for unknown type")
	}
}

func TestValidCommitment(t *testing.T) {
	p := newTestPolicy()
	e := entry.CommitmentEntry{
		EntryType:      entry.EntryTypeCommitment,
		JobID:          "job-c1",
		CommitmentHash: make([]byte, 32),
		CoordSignature: make([]byte, 64),
		SubmitterID:    "coord-1",
		Timestamp:      1700000000,
	}
	data, _ := entry.Marshal(e)
	if err := p.Validate(entry.EntryTypeCommitment, data); err != nil {
		t.Fatalf("valid Commitment rejected: %v", err)
	}
}

func TestCommitmentMissingOrInvalidFields(t *testing.T) {
	p := newTestPolicy()
	good := entry.CommitmentEntry{
		EntryType:      entry.EntryTypeCommitment,
		JobID:          "job-c1",
		CommitmentHash: make([]byte, 32),
		CoordSignature: make([]byte, 64),
		SubmitterID:    "coord-1",
		Timestamp:      1700000000,
	}

	tests := []struct {
		name  string
		mutate func(e *entry.CommitmentEntry)
	}{
		{"missing job_id", func(e *entry.CommitmentEntry) { e.JobID = "" }},
		{"hash too short", func(e *entry.CommitmentEntry) { e.CommitmentHash = make([]byte, 16) }},
		{"hash too long", func(e *entry.CommitmentEntry) { e.CommitmentHash = make([]byte, 64) }},
		{"missing signature", func(e *entry.CommitmentEntry) { e.CoordSignature = nil }},
		{"missing submitter", func(e *entry.CommitmentEntry) { e.SubmitterID = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := good
			tc.mutate(&e)
			data, _ := entry.Marshal(e)
			if err := p.Validate(entry.EntryTypeCommitment, data); err == nil {
				t.Fatalf("%s: expected rejection", tc.name)
			}
		})
	}
}
