package receipt

import (
	"crypto"
	"crypto/ed25519"
	"fmt"

	"github.com/veraison/go-cose"
)

const (
	// SCITT inclusion proof header label
	HeaderLabelInclusionProof int64 = 395
)

// InclusionProofStruct is the CBOR structure embedded in header label 395.
type InclusionProofStruct struct {
	LeafIndex     uint64   `cbor:"0,keyasint"`
	TreeSize      uint64   `cbor:"1,keyasint"`
	InclusionPath [][]byte `cbor:"2,keyasint"`
}

// Generator generates SCITT-aligned inclusion receipts.
type Generator struct {
	signer cose.Signer
	key    ed25519.PrivateKey
}

// NewGenerator creates a receipt generator from an Ed25519 private key.
func NewGenerator(key ed25519.PrivateKey) (*Generator, error) {
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, key)
	if err != nil {
		return nil, fmt.Errorf("creating COSE signer: %w", err)
	}
	return &Generator{signer: signer, key: key}, nil
}

// Generate creates a COSE_Sign1 inclusion receipt.
func (g *Generator) Generate(leafIndex, treeSize uint64, rootHash []byte, inclusionPath [][]byte) ([]byte, error) {
	proofStruct := InclusionProofStruct{
		LeafIndex:     leafIndex,
		TreeSize:      treeSize,
		InclusionPath: inclusionPath,
	}

	msg := cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm:                  cose.AlgorithmEdDSA,
				cose.HeaderLabelContentType:                "application/cbor",
				HeaderLabelInclusionProof:                  proofStruct,
			},
			Unprotected: cose.UnprotectedHeader{},
		},
		Payload: rootHash,
	}

	if err := msg.Sign(nil, nil, g.signer); err != nil {
		return nil, fmt.Errorf("signing receipt: %w", err)
	}

	return msg.MarshalCBOR()
}

// Verify verifies a COSE_Sign1 inclusion receipt.
func Verify(receiptCBOR []byte, rootHash []byte, operatorPubKey ed25519.PublicKey) (*InclusionProofStruct, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(receiptCBOR); err != nil {
		return nil, fmt.Errorf("decoding receipt: %w", err)
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, operatorPubKey)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("receipt signature invalid: %w", err)
	}

	// Extract inclusion proof from protected header
	raw, ok := msg.Headers.Protected[HeaderLabelInclusionProof]
	if !ok {
		return nil, fmt.Errorf("receipt missing inclusion proof (label %d)", HeaderLabelInclusionProof)
	}

	// The proof struct may be a map or struct depending on CBOR decode
	proofMap, ok := raw.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("inclusion proof has unexpected type %T", raw)
	}

	proof := &InclusionProofStruct{}

	if v, ok := proofMap[int64(0)]; ok {
		proof.LeafIndex = toUint64(v)
	}
	if v, ok := proofMap[int64(1)]; ok {
		proof.TreeSize = toUint64(v)
	}
	if v, ok := proofMap[int64(2)]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if b, ok := item.([]byte); ok {
					proof.InclusionPath = append(proof.InclusionPath, b)
				}
			}
		}
	}

	return proof, nil
}

func toUint64(v interface{}) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		return uint64(n)
	default:
		return 0
	}
}

// PublicKey returns the public key from the generator's private key.
func (g *Generator) PublicKey() crypto.PublicKey {
	return g.key.Public()
}
