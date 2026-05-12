package entry

const (
	EntryTypeHA         = 1
	EntryTypeLA         = 2
	EntryTypeConfig     = 3
	EntryTypeCommitment = 4
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

// CommitmentEntry records a coordinator-signed pre-execution commitment to a
// job's inputs. The full Job Acceptance Commitment (JAC) payload — script
// hash, dataset binding, policy ID, freshness nonce — stays with the
// researcher; the log records only CommitmentHash = SHA-256 of that payload,
// preserving privacy while providing a public anchor for the submission.
//
// A held JAC paired with no corresponding HA entry within the maximum merge
// delay is non-repudiable evidence of operator suppression: the commitment
// hash is publicly logged before execution, and the post-execution
// attestation is cryptographically bound to it via the same freshness nonce.
type CommitmentEntry struct {
	EntryType      int    `cbor:"0,keyasint"`
	JobID          string `cbor:"1,keyasint"` // H(researcher_nonce || coordinator_nonce)
	CommitmentHash []byte `cbor:"2,keyasint"` // SHA-256 of full JAC payload (32 bytes)
	CoordSignature []byte `cbor:"3,keyasint"` // Coordinator signature over (job_id || commitment_hash)
	SubmitterID    string `cbor:"4,keyasint"`
	Timestamp      int64  `cbor:"5,keyasint"`
}
