package merkle

import "github.com/transparency-dev/merkle/rfc6962"

var hasher = rfc6962.DefaultHasher

// HashLeaf computes the RFC 9162 leaf hash: SHA-256(0x00 || data).
func HashLeaf(data []byte) []byte {
	return hasher.HashLeaf(data)
}

// HashChildren computes the RFC 9162 interior hash: SHA-256(0x01 || left || right).
func HashChildren(left, right []byte) []byte {
	return hasher.HashChildren(left, right)
}
