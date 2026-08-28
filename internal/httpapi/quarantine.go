package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/GoreeCloud/goreecloud-drive/internal/quarantine"
)

func quarantineApplyHandler(target quarantine.Target, serviceToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorizeWardveilService(w, r, serviceToken) {
			return
		}
		if target == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "quarantine target unavailable"})
			return
		}
		var request quarantine.ApplyRequest
		if err := decodeJSON(w, r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		result := target.Apply(r.Context(), request)
		switch result.Status {
		case "applied", "already_applied":
			writeJSON(w, http.StatusOK, result)
		case "failed":
			writeJSON(w, http.StatusConflict, result)
		default:
			writeJSON(w, http.StatusServiceUnavailable, result)
		}
	}
}

func quarantineReadHandler(target quarantine.Target, serviceToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorizeWardveilService(w, r, serviceToken) {
			return
		}
		if target == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "quarantine target unavailable"})
			return
		}
		var request quarantine.ReadRequest
		if err := decodeJSON(w, r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		result := target.Read(r.Context(), request)
		if result.Status == "unknown" {
			writeJSON(w, http.StatusServiceUnavailable, result)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func authorizeWardveilService(w http.ResponseWriter, r *http.Request, expected string) bool {
	if strings.TrimSpace(expected) == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service authorization unavailable"})
		return false
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return false
	}
	provided := strings.TrimPrefix(header, prefix)
	providedDigest := sha256.Sum256([]byte(provided))
	expectedDigest := sha256.Sum256([]byte(expected))
	if subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) != 1 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return false
	}
	return true
}
