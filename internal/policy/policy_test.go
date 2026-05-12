package policy

import (
	"crypto/ed25519"
	"crypto/rand"
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

// newCommitmentTestPolicy builds a Policy with one registered coordinator key
// and returns the policy plus the private key for signing test entries.
func newCommitmentTestPolicy(t *testing.T) (*Policy, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	submitterID := "coord-1"
	p := New(Config{
		AllowedPCR0:     []string{"abc123"},
		FreshnessWindow: 86400,
		CoordinatorKeys: map[string]ed25519.PublicKey{
			submitterID: pub,
		},
	})
	return p, priv, submitterID
}

// signedCommitment builds a CommitmentEntry with a valid coordinator signature
// over (job_id || commitment_hash).
func signedCommitment(jobID string, hash []byte, priv ed25519.PrivateKey, submitterID string) entry.CommitmentEntry {
	signed := append([]byte(jobID), hash...)
	sig := ed25519.Sign(priv, signed)
	return entry.CommitmentEntry{
		EntryType:      entry.EntryTypeCommitment,
		JobID:          jobID,
		CommitmentHash: hash,
		CoordSignature: sig,
		SubmitterID:    submitterID,
		Timestamp:      1700000000,
	}
}

func TestValidCommitment(t *testing.T) {
	p, priv, submitter := newCommitmentTestPolicy(t)
	e := signedCommitment("job-c1", make([]byte, 32), priv, submitter)
	data, _ := entry.Marshal(e)
	if err := p.Validate(entry.EntryTypeCommitment, data); err != nil {
		t.Fatalf("valid Commitment rejected: %v", err)
	}
}

func TestCommitmentMissingOrInvalidFields(t *testing.T) {
	p, priv, submitter := newCommitmentTestPolicy(t)
	good := signedCommitment("job-c1", make([]byte, 32), priv, submitter)

	tests := []struct {
		name   string
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

func TestCommitmentSignatureVerification(t *testing.T) {
	p, priv, submitter := newCommitmentTestPolicy(t)
	jobID := "job-sig-1"
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	t.Run("tampered job_id rejected", func(t *testing.T) {
		e := signedCommitment(jobID, hash, priv, submitter)
		e.JobID = "job-sig-2" // mutate after signing
		data, _ := entry.Marshal(e)
		if err := p.Validate(entry.EntryTypeCommitment, data); err == nil {
			t.Fatal("expected rejection for tampered job_id")
		}
	})

	t.Run("tampered commitment_hash rejected", func(t *testing.T) {
		e := signedCommitment(jobID, hash, priv, submitter)
		tampered := make([]byte, 32)
		copy(tampered, hash)
		tampered[0] ^= 0xFF
		e.CommitmentHash = tampered
		data, _ := entry.Marshal(e)
		if err := p.Validate(entry.EntryTypeCommitment, data); err == nil {
			t.Fatal("expected rejection for tampered commitment_hash")
		}
	})

	t.Run("garbage signature rejected", func(t *testing.T) {
		e := signedCommitment(jobID, hash, priv, submitter)
		e.CoordSignature = make([]byte, ed25519.SignatureSize) // all-zero sig
		data, _ := entry.Marshal(e)
		if err := p.Validate(entry.EntryTypeCommitment, data); err == nil {
			t.Fatal("expected rejection for garbage signature")
		}
	})

	t.Run("unknown submitter rejected", func(t *testing.T) {
		e := signedCommitment(jobID, hash, priv, "coord-unregistered")
		data, _ := entry.Marshal(e)
		if err := p.Validate(entry.EntryTypeCommitment, data); err == nil {
			t.Fatal("expected rejection for unknown submitter")
		}
	})

	t.Run("signature from different key rejected", func(t *testing.T) {
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		e := signedCommitment(jobID, hash, otherPriv, submitter) // signed by wrong key, claims registered submitter
		data, _ := entry.Marshal(e)
		if err := p.Validate(entry.EntryTypeCommitment, data); err == nil {
			t.Fatal("expected rejection for signature from wrong key")
		}
	})
}
