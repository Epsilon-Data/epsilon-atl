package entry

const (
	EntryTypeHA     = 1
	EntryTypeLA     = 2
	EntryTypeConfig = 3
)

// HAEntry is a High-Assurance attestation entry wrapping a hardware-signed
// attestation document from any supported TEE platform.
type HAEntry struct {
	EntryType   int    `cbor:"0,keyasint"`
	JobID       string `cbor:"1,keyasint"`
	TEEPlatform string `cbor:"2,keyasint"`
	Attestation []byte `cbor:"3,keyasint"` // COSE_Sign1 from enclave
	Nonce       []byte `cbor:"4,keyasint"`
	SubmitterID string `cbor:"5,keyasint"`
}

// LAEntry is a Low-Assurance failure record signed by the coordinator.
type LAEntry struct {
	EntryType      int    `cbor:"0,keyasint"`
	JobID          string `cbor:"1,keyasint"`
	ErrorClass     string `cbor:"2,keyasint"`
	ErrorDetail    string `cbor:"3,keyasint"`
	SubmitterID    string `cbor:"4,keyasint"`
	CoordSignature []byte `cbor:"5,keyasint"`
}

// ConfigEntry records key lifecycle events.
type ConfigEntry struct {
	EntryType   int    `cbor:"0,keyasint"`
	Event       string `cbor:"1,keyasint"` // key_creation, key_rotation, key_revocation
	SubjectKey  []byte `cbor:"2,keyasint"` // public key being acted on
	Predecessor []byte `cbor:"3,keyasint,omitempty"` // predecessor signature (for rotation)
	SubmitterID string `cbor:"4,keyasint"`
	Timestamp   int64  `cbor:"5,keyasint"`
}
