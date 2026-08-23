package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoreeCloud/goreecloud-drive/internal/config"
)

func TestStatusIsExplicitlyDevelopment(t *testing.T) {
	testDir := t.TempDir()
	server := New(config.Config{Bind: "127.0.0.1:0", WebDir: testDir}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	server.http.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), `"lifecycle":"Development"`) {
		t.Fatalf("response does not preserve lifecycle boundary: %s", recorder.Body.String())
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
}

func TestUnknownAPIPathDoesNotMasqueradeAsSuccess(t *testing.T) {
	testDir := t.TempDir()
	server := New(config.Config{Bind: "127.0.0.1:0", WebDir: testDir}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/not-real", nil)
	server.http.Handler.ServeHTTP(recorder, request)

	if recorder.Code == http.StatusOK {
		t.Fatal("unknown API path returned success")
	}
}
