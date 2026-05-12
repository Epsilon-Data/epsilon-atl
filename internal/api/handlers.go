package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
	"github.com/Epsilon-Data/epsilon-atl/internal/merkle"
	"github.com/Epsilon-Data/epsilon-atl/internal/policy"
)

func (s *Server) handleSubmitEntry(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading body")
		return
	}

	// Authenticate
	submitterID, err := verifyCoordinatorAuth(r, body, s.allowedSubmitters, s.coordinatorKeys)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Peek entry type
	tPeek := time.Now()
	entryType, err := entry.EntryType(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid entry: "+err.Error())
		return
	}

	// Policy validation
	tPolicy := time.Now()
	if s.policy != nil {
		if err := s.policy.Validate(entryType, body); err != nil {
			writeError(w, http.StatusBadRequest, "policy violation: "+err.Error())
			return
		}
	}

	// Compute leaf hash
	tHash := time.Now()
	leafHash := merkle.HashLeaf(body)

	// Dedup check
	tDedup := time.Now()
	exists, err := s.store.LeafHashExists(leafHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dedup check failed")
		return
	}
	if exists {
		writeError(w, http.StatusConflict, "duplicate entry")
		return
	}

	// Extract metadata from entry
	jobID, teePlatform := extractMetadata(entryType, body)

	// Store entry
	tInsert := time.Now()
	leafIndex, err := s.store.AppendEntry(entryType, body, leafHash, jobID, teePlatform, submitterID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storing entry")
		return
	}

	// Append to tree
	tTree := time.Now()
	if err := s.tree.Append(leafHash); err != nil {
		writeError(w, http.StatusInternalServerError, "tree append")
		return
	}

	// Sign new STH
	tSign := time.Now()
	rootHash, err := s.tree.RootHash()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "computing root")
		return
	}
	sthVal, err := s.signer.Sign(s.tree.Size(), rootHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing STH")
		return
	}
	if err := s.store.SaveSTH(sthVal); err != nil {
		writeError(w, http.StatusInternalServerError, "saving STH")
		return
	}

	// Save tree state (compact hashes only — nodes live in memory)
	tState := time.Now()
	size, hashes := s.tree.CompactState()
	if err := s.store.SaveTreeState(size, hashes, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "saving tree state")
		return
	}

	// Generate inclusion receipt if receipt generator is available
	tReceipt := time.Now()
	var receiptBytes []byte
	if s.receiptGen != nil {
		treeSize := s.tree.Size()
		proofHashes, err := s.tree.InclusionProof(uint64(leafIndex), treeSize)
		if err == nil {
			receiptBytes, _ = s.receiptGen.Generate(uint64(leafIndex), treeSize, rootHash, proofHashes)
		}
	}

	tDone := time.Now()

	// Return per-step timing in response for benchmarking.
	// All values in microseconds.
	timing := map[string]interface{}{
		"auth_us":        tPeek.Sub(t0).Microseconds(),
		"policy_us":      tHash.Sub(tPolicy).Microseconds(),
		"leaf_hash_us":   tDedup.Sub(tHash).Microseconds(),
		"dedup_check_us": tInsert.Sub(tDedup).Microseconds(),
		"db_insert_us":   tTree.Sub(tInsert).Microseconds(),
		"tree_append_us": tSign.Sub(tTree).Microseconds(),
		"sth_sign_us":    tState.Sub(tSign).Microseconds(),
		"state_save_us":  tReceipt.Sub(tState).Microseconds(),
		"receipt_gen_us": tDone.Sub(tReceipt).Microseconds(),
		"total_us":       tDone.Sub(t0).Microseconds(),
	}

	resp := map[string]interface{}{
		"leaf_index": leafIndex,
		"tree_size":  sthVal.TreeSize,
		"root_hash":  sthVal.RootHash,
		"timestamp":  sthVal.Timestamp,
		"timing":     timing,
	}
	if receiptBytes != nil {
		resp["receipt"] = receiptBytes
	}
	writeCBOR(w, http.StatusCreated, resp)
}

func (s *Server) handleGetEntry(w http.ResponseWriter, r *http.Request) {
	indexStr := r.PathValue("index")
	index, err := strconv.ParseInt(indexStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid index")
		return
	}

	entryCBOR, err := s.store.GetEntry(index)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("entry %d not found", index))
		return
	}

	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	w.Write(entryCBOR)
}

func (s *Server) handleInclusionProof(w http.ResponseWriter, r *http.Request) {
	indexStr := r.PathValue("index")
	index, err := strconv.ParseUint(indexStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid index")
		return
	}

	treeSize := s.tree.Size()
	if tsStr := r.URL.Query().Get("tree_size"); tsStr != "" {
		treeSize, err = strconv.ParseUint(tsStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid tree_size")
			return
		}
	}

	proofHashes, err := s.tree.InclusionProof(index, treeSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := map[string]interface{}{
		"leaf_index":  index,
		"tree_size":   treeSize,
		"proof":       proofHashes,
	}
	writeCBOR(w, http.StatusOK, resp)
}

func (s *Server) handleGetSTH(w http.ResponseWriter, r *http.Request) {
	sthVal, err := s.store.LatestSTH()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "fetching STH")
		return
	}
	if sthVal == nil {
		writeError(w, http.StatusNotFound, "no STH available")
		return
	}
	writeCBOR(w, http.StatusOK, sthVal)
}

func (s *Server) handleConsistencyProof(w http.ResponseWriter, r *http.Request) {
	firstStr := r.URL.Query().Get("first")
	secondStr := r.URL.Query().Get("second")
	if firstStr == "" || secondStr == "" {
		writeError(w, http.StatusBadRequest, "first and second query params required")
		return
	}

	first, err := strconv.ParseUint(firstStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid first")
		return
	}
	second, err := strconv.ParseUint(secondStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid second")
		return
	}

	proofHashes, err := s.tree.ConsistencyProof(first, second)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := map[string]interface{}{
		"first":  first,
		"second": second,
		"proof":  proofHashes,
	}
	writeCBOR(w, http.StatusOK, resp)
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	platforms := make([]string, 0, len(policy.SupportedPlatforms))
	for p := range policy.SupportedPlatforms {
		platforms = append(platforms, p)
	}
	resp := map[string]interface{}{
		"operator_key":        s.operatorPubKeyBytes,
		"mmd_seconds":         s.mmdSeconds,
		"version":             "0.2.0",
		"supported_platforms": platforms,
	}
	writeCBOR(w, http.StatusOK, resp)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeCBOR(w, http.StatusOK, map[string]string{"status": "ok"})
}

func extractMetadata(entryType int, data []byte) (jobID, teePlatform string) {
	switch entryType {
	case entry.EntryTypeHA:
		var e entry.HAEntry
		if entry.Unmarshal(data, &e) == nil {
			return e.JobID, e.TEEPlatform
		}
	case entry.EntryTypeLA:
		var e entry.LAEntry
		if entry.Unmarshal(data, &e) == nil {
			return e.JobID, ""
		}
	case entry.EntryTypeCommitment:
		var e entry.CommitmentEntry
		if entry.Unmarshal(data, &e) == nil {
			return e.JobID, ""
		}
	}
	return "", ""
}
