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

func TestWriteUploadErrorMapsUnknownFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeUploadError(recorder, errors.New("boom"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want %d", recorder.Code, http.StatusInternalServerError)
	}
}
