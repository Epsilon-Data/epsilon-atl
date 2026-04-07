package sth

// SignedTreeHead is a signed commitment to the tree state.
type SignedTreeHead struct {
	TreeSize  uint64 `cbor:"1,keyasint"`
	RootHash  []byte `cbor:"2,keyasint"`
	Timestamp int64  `cbor:"3,keyasint"`
	Signature []byte `cbor:"4,keyasint"`
}

// TreeHeadPayload is the portion of the STH that gets signed (no signature field).
type TreeHeadPayload struct {
	TreeSize  uint64 `cbor:"1,keyasint"`
	RootHash  []byte `cbor:"2,keyasint"`
	Timestamp int64  `cbor:"3,keyasint"`
}
