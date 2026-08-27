package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoreeCloud/goreecloud-drive/internal/uploads"
)

func TestWriteUploadErrorMapsOffsetConflict(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeUploadError(recorder, uploads.ErrOffsetMismatch)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d want %d", recorder.Code, http.StatusConflict)
	}
}

func TestWriteUploadErrorMapsSecurityBlockedWithoutLeakingEvidence(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeUploadError(recorder, uploads.ErrSecurityBlocked)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want %d", recorder.Code, http.StatusUnprocessableEntity)
	}
	if recorder.Body.String() != "{\"error\":\"upload blocked by security policy\"}\n" {
		t.Fatalf("unexpected response body %q", recorder.Body.String())
	}
}

func TestWriteUploadErrorMapsSecurityUnavailable(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeUploadError(recorder, uploads.ErrSecurityUnavailable)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}

func TestWriteUploadErrorMapsUnknownFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeUploadError(recorder, errors.New("boom"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want %d", recorder.Code, http.StatusInternalServerError)
	}
}
