package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoreeCloud/goreecloud-drive/internal/authn"
	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
	"github.com/GoreeCloud/goreecloud-drive/internal/config"
	"github.com/GoreeCloud/goreecloud-drive/internal/spaceaccess"
)

type fixedPrincipal struct{ accountID string }

func (f fixedPrincipal) Resolve(context.Context, *http.Request) (authn.Principal, error) {
	return authn.Principal{AccountID: f.accountID}, nil
}

type httpMemberships map[string]authz.Role

func (m httpMemberships) RoleForAccount(_ context.Context, accountID, spaceID string) (authz.Role, error) {
	role, ok := m[accountID+":"+spaceID]
	if !ok {
		return "", spaceaccess.ErrNotMember
	}
	return role, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestStatusIsExplicitlyDevelopment(t *testing.T) {
	testDir := t.TempDir()
	server := New(config.Config{Bind: "127.0.0.1:0", WebDir: testDir}, testLogger())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	server.http.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), `"lifecycle":"Development"`) {
		t.Fatalf("response does not preserve lifecycle boundary: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"authentication":false`) {
		t.Fatalf("status must not claim production authentication: %s", recorder.Body.String())
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
}

func TestCapabilityEndpointDefaultsToUnauthenticated(t *testing.T) {
	server := New(config.Config{Bind: "127.0.0.1:0", WebDir: t.TempDir()}, testLogger())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/alice-private/capabilities/read", nil)
	server.http.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestCapabilityEndpointEnforcesMembershipAndRole(t *testing.T) {
	deps := Dependencies{
		Principals: fixedPrincipal{accountID: "bob"},
		Memberships: httpMemberships{
			"bob:shared":        authz.RoleViewer,
			"bob:dropbox-alice": authz.RoleDropOnly,
		},
	}
	server := NewWithDependencies(config.Config{Bind: "127.0.0.1:0", WebDir: t.TempDir()}, testLogger(), deps)

	tests := []struct {
		path string
		want int
	}{
		{path: "/api/v1/spaces/shared/capabilities/read", want: http.StatusOK},
		{path: "/api/v1/spaces/shared/capabilities/create_file", want: http.StatusForbidden},
		{path: "/api/v1/spaces/alice-private/capabilities/read", want: http.StatusForbidden},
		{path: "/api/v1/spaces/dropbox-alice/capabilities/create_file", want: http.StatusOK},
		{path: "/api/v1/spaces/dropbox-alice/capabilities/list", want: http.StatusForbidden},
		{path: "/api/v1/spaces/shared/capabilities/unknown", want: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, tt.path, nil)
			server.http.Handler.ServeHTTP(recorder, request)
			if recorder.Code != tt.want {
				t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, tt.want, recorder.Body.String())
			}
		})
	}
}

func TestUnknownAPIPathDoesNotMasqueradeAsSuccess(t *testing.T) {
	testDir := t.TempDir()
	server := New(config.Config{Bind: "127.0.0.1:0", WebDir: testDir}, testLogger())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/not-real", nil)
	server.http.Handler.ServeHTTP(recorder, request)

	if recorder.Code == http.StatusOK {
		t.Fatal("unknown API path returned success")
	}
}
