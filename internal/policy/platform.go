package policy

// SupportedPlatforms lists TEE platforms the ATL accepts.
// The ATL is TEE-agnostic: any platform that produces a hardware-signed
// attestation document with an application-defined data field can submit entries.
//
// Platform-specific attestation verification is optional and pluggable via
// AttestationVerifier. When no verifier is registered for a platform,
// the ATL accepts the entry based on structural validation only.
// This is the correct default: the coordinator (submitter) is responsible for
// verifying attestation before forwarding to the ATL. The ATL's role is
// append-only logging, not attestation appraisal.
var SupportedPlatforms = map[string]PlatformInfo{
	"aws-nitro": {
		Name:               "AWS Nitro Enclaves",
		AttestationFormat:  "COSE_Sign1",
		SignatureAlgorithm: "ECDSA P-384",
		AppDataField:       "user_data (1024 bytes)",
		MeasurementFields:  []string{"PCR0", "PCR1", "PCR2"},
	},
	"intel-sgx": {
		Name:               "Intel SGX",
		AttestationFormat:  "SGX Quote (v3/v4)",
		SignatureAlgorithm: "ECDSA P-256",
		AppDataField:       "report_data (64 bytes)",
		MeasurementFields:  []string{"MRENCLAVE", "MRSIGNER"},
	},
	"intel-tdx": {
		Name:               "Intel TDX",
		AttestationFormat:  "TD Quote",
		SignatureAlgorithm: "ECDSA P-384",
		AppDataField:       "report_data (64 bytes)",
		MeasurementFields:  []string{"MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"},
	},
	"amd-sev-snp": {
		Name:               "AMD SEV-SNP",
		AttestationFormat:  "Attestation Report",
		SignatureAlgorithm: "ECDSA P-384",
		AppDataField:       "REPORT_DATA (64 bytes)",
		MeasurementFields:  []string{"MEASUREMENT", "HOST_DATA"},
	},
	"arm-cca": {
		Name:               "Arm CCA (Realms)",
		AttestationFormat:  "CCA Platform Token",
		SignatureAlgorithm: "ECDSA P-256/P-384",
		AppDataField:       "challenge (64 bytes)",
		MeasurementFields:  []string{"RIM", "REM"},
	},
}

// PlatformInfo describes a TEE platform's attestation characteristics.
type PlatformInfo struct {
	Name               string   // Human-readable name
	AttestationFormat  string   // Wire format of attestation document
	SignatureAlgorithm string   // Signature algorithm used by hardware
	AppDataField       string   // Application-defined data field name and size
	MeasurementFields  []string // Platform measurement identifiers
}

// AttestationVerifier performs platform-specific attestation verification.
// Implementations should verify the attestation document's signature chain,
// check platform measurements against an allowlist, and validate freshness.
//
// Returning nil means the attestation is valid.
// The ATL does not require a verifier for every platform — structural
// validation is the minimum. Verifiers are optional per deployment.
type AttestationVerifier interface {
	// Verify checks the attestation document against platform-specific rules.
	// attestation is the raw hardware-signed bytes.
	// allowedMeasurements is the operator-configured allowlist (may be empty).
	Verify(attestation []byte, allowedMeasurements []string) error
}

// IsSupportedPlatform checks if a TEE platform identifier is recognized.
func IsSupportedPlatform(platform string) bool {
	_, ok := SupportedPlatforms[platform]
	return ok
}
