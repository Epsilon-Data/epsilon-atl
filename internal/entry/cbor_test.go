package entry

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHAEntryRoundtrip(t *testing.T) {
	orig := HAEntry{
		EntryType:   EntryTypeHA,
		JobID:       "job-001",
		TEEPlatform: "aws-nitro",
		Attestation: []byte{0xDE, 0xAD},
		Nonce:       []byte{0xBE, 0xEF},
		SubmitterID: "coord-1",
	}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded HAEntry
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.EntryType != orig.EntryType || decoded.JobID != orig.JobID ||
		decoded.TEEPlatform != orig.TEEPlatform || decoded.SubmitterID != orig.SubmitterID {
		t.Fatalf("roundtrip mismatch: got %+v", decoded)
	}
	if !bytes.Equal(decoded.Attestation, orig.Attestation) || !bytes.Equal(decoded.Nonce, orig.Nonce) {
		t.Fatalf("byte field mismatch")
	}
}

func TestLAEntryRoundtrip(t *testing.T) {
	orig := LAEntry{
		EntryType:      EntryTypeLA,
		JobID:          "job-002",
		ErrorClass:     "timeout",
		ErrorDetail:    "enclave did not respond",
		SubmitterID:    "coord-1",
		CoordSignature: []byte{0x01, 0x02, 0x03},
	}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded LAEntry
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ErrorClass != orig.ErrorClass || decoded.ErrorDetail != orig.ErrorDetail {
		t.Fatalf("roundtrip mismatch: got %+v", decoded)
	}
}

func TestConfigEntryRoundtrip(t *testing.T) {
	orig := ConfigEntry{
		EntryType:   EntryTypeConfig,
		Event:       "key_creation",
		SubjectKey:  []byte{0xAA, 0xBB},
		SubmitterID: "admin",
		Timestamp:   1700000000,
	}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ConfigEntry
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Event != orig.Event || decoded.Timestamp != orig.Timestamp {
		t.Fatalf("roundtrip mismatch: got %+v", decoded)
	}
	if decoded.Predecessor != nil {
		t.Fatalf("omitempty predecessor should be nil, got %v", decoded.Predecessor)
	}
}

func TestDeterminism(t *testing.T) {
	e := HAEntry{
		EntryType:   EntryTypeHA,
		JobID:       "job-det",
		TEEPlatform: "aws-nitro",
		Attestation: []byte{0x01},
		Nonce:       []byte{0x02},
		SubmitterID: "coord-1",
	}
	d1, _ := Marshal(e)
	d2, _ := Marshal(e)
	if !bytes.Equal(d1, d2) {
		t.Fatalf("non-deterministic: %x != %x", d1, d2)
	}
}

func TestEntryTypePeek(t *testing.T) {
	ha := HAEntry{EntryType: EntryTypeHA, JobID: "j", TEEPlatform: "p", SubmitterID: "s"}
	data, _ := Marshal(ha)
	typ, err := EntryType(data)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if typ != EntryTypeHA {
		t.Fatalf("expected %d, got %d", EntryTypeHA, typ)
	}

	la := LAEntry{EntryType: EntryTypeLA, JobID: "j", ErrorClass: "e", SubmitterID: "s"}
	data, _ = Marshal(la)
	typ, err = EntryType(data)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if typ != EntryTypeLA {
		t.Fatalf("expected %d, got %d", EntryTypeLA, typ)
	}

	cm := CommitmentEntry{EntryType: EntryTypeCommitment, JobID: "j", SubmitterID: "s"}
	data, _ = Marshal(cm)
	typ, err = EntryType(data)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if typ != EntryTypeCommitment {
		t.Fatalf("expected %d, got %d", EntryTypeCommitment, typ)
	}
}

func TestCommitmentEntryRoundtrip(t *testing.T) {
	orig := CommitmentEntry{
		EntryType:      EntryTypeCommitment,
		JobID:          "job-c01",
		CommitmentHash: bytes.Repeat([]byte{0x00}, 32),
		CoordSignature: bytes.Repeat([]byte{0xAA}, 64),
		SubmitterID:    "coord-1",
		Timestamp:      1700000000,
	}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded CommitmentEntry
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.EntryType != orig.EntryType || decoded.JobID != orig.JobID ||
		decoded.SubmitterID != orig.SubmitterID || decoded.Timestamp != orig.Timestamp {
		t.Fatalf("roundtrip mismatch: got %+v", decoded)
	}
	if !bytes.Equal(decoded.CommitmentHash, orig.CommitmentHash) ||
		!bytes.Equal(decoded.CoordSignature, orig.CoordSignature) {
		t.Fatalf("byte field mismatch")
	}
}

// TestCrossLanguageVectors verifies Go output matches Python cbor2.dumps(..., canonical=True).
// Canonical CBOR for: {0:1, 1:"job-001", 2:"aws-nitro", 3:b"\xde\xad", 4:b"\xbe\xef", 5:"coord-1"}
// Verified with: python3 -c "import cbor2; print(cbor2.dumps({0:1, 1:'job-001', 2:'aws-nitro', 3:b'\xde\xad', 4:b'\xbe\xef', 5:'coord-1'}, canonical=True).hex())"
func TestCrossLanguageVectors(t *testing.T) {
	// Expected canonical CBOR hex (RFC 8949 Section 4.2.1):
	// a6           -- map(6)
	// 00           -- key 0 (unsigned 0)
	// 01           -- value 1 (unsigned 1)
	// 01           -- key 1
	// 67 6a6f622d303031 -- text(7) "job-001"
	// 02           -- key 2
	// 69 6177732d6e6974726f -- text(9) "aws-nitro"
	// 03           -- key 3
	// 42 dead      -- bytes(2)
	// 04           -- key 4
	// 42 beef      -- bytes(2)
	// 05           -- key 5
	// 67 636f6f72642d31 -- text(7) "coord-1"
	expectedHex := "a6000101676a6f622d30303102696177732d6e6974726f0342dead0442beef0567636f6f72642d31"

	e := HAEntry{
		EntryType:   EntryTypeHA,
		JobID:       "job-001",
		TEEPlatform: "aws-nitro",
		Attestation: []byte{0xDE, 0xAD},
		Nonce:       []byte{0xBE, 0xEF},
		SubmitterID: "coord-1",
	}
	goBytes, err := Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	goHex := hex.EncodeToString(goBytes)
	if goHex != expectedHex {
		t.Fatalf("cross-language mismatch:\n  got:  %s\n  want: %s", goHex, expectedHex)
	}
}

// TestCommitmentCrossLanguageVector verifies Go output matches Python cbor2 reference.
// Verified with: python3 -c "import cbor2; print(cbor2.dumps({0:4, 1:'job-c01', 2:bytes(32), 3:bytes.fromhex('aa'*64), 4:'coord-1', 5:1700000000}, canonical=True).hex())"
func TestCommitmentCrossLanguageVector(t *testing.T) {
	expectedHex := "a6000401676a6f622d6330310258200000000000000000000000000000000000000000000000000000000000000000035840aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0467636f6f72642d31051a6553f100"

	e := CommitmentEntry{
		EntryType:      EntryTypeCommitment,
		JobID:          "job-c01",
		CommitmentHash: bytes.Repeat([]byte{0x00}, 32),
		CoordSignature: bytes.Repeat([]byte{0xAA}, 64),
		SubmitterID:    "coord-1",
		Timestamp:      1700000000,
	}
	goBytes, err := Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	goHex := hex.EncodeToString(goBytes)
	if goHex != expectedHex {
		t.Fatalf("cross-language mismatch:\n  got:  %s\n  want: %s", goHex, expectedHex)
	}
}
