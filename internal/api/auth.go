package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
)

// verifyCoordinatorAuth checks the X-Submitter-ID and X-Coordinator-Signature headers.
func verifyCoordinatorAuth(r *http.Request, body []byte, allowedSubmitters []string, coordinatorKeys map[string]ed25519.PublicKey) (string, error) {
	submitterID := r.Header.Get("X-Submitter-ID")
	if submitterID == "" {
		return "", fmt.Errorf("missing X-Submitter-ID header")
	}

	// Check if submitter is allowed
	if len(allowedSubmitters) > 0 {
		allowed := false
		for _, s := range allowedSubmitters {
			if s == submitterID {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("submitter %q not in allowed list", submitterID)
		}
	}

	sigHeader := r.Header.Get("X-Coordinator-Signature")
	if sigHeader == "" {
		return "", fmt.Errorf("missing X-Coordinator-Signature header")
	}
	sig, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding: %w", err)
	}

	pubKey, ok := coordinatorKeys[submitterID]
	if !ok {
		return "", fmt.Errorf("no public key registered for submitter %q", submitterID)
	}
	if !ed25519.Verify(pubKey, body, sig) {
		return "", fmt.Errorf("signature verification failed for submitter %q", submitterID)
	}
	return submitterID, nil
}
