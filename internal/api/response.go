package api

import (
	"net/http"

	"github.com/Epsilon-Data/epsilon-atl/internal/entry"
)

func writeCBOR(w http.ResponseWriter, status int, v interface{}) {
	data, err := entry.Marshal(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encoding response")
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(status)
	w.Write(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	resp := map[string]string{"error": msg}
	data, err := entry.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(status)
	w.Write(data)
}
