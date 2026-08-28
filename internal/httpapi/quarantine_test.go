package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoreeCloud/goreecloud-drive/internal/quarantine"
)

type fakeQuarantineTarget struct {
	apply quarantine.ApplyResult
	read  quarantine.ReadResult
}

func (f fakeQuarantineTarget) Apply(context.Context, quarantine.ApplyRequest) quarantine.ApplyResult {
	return f.apply
}

func (f fakeQuarantineTarget) Read(context.Context, quarantine.ReadRequest) quarantine.ReadResult {
	return f.read
}

func TestQuarantineApplyRequiresServiceAuthorization(t *testing.T) {
	handler := quarantineApplyHandler(fakeQuarantineTarget{}, "secret-token")
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/wardveil/quarantine/apply", strings.NewReader(`{}`))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("expected concealed unauthorized route, got %d", res.Code)
	}
}

func TestQuarantineApplyFailsClosedWhenTokenUnconfigured(t *testing.T) {
	handler := quarantineApplyHandler(fakeQuarantineTarget{}, "")
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/wardveil/quarantine/apply", strings.NewReader(`{}`))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable service authorization, got %d", res.Code)
	}
}

func TestQuarantineApplyReturnsTargetReadbackProvenance(t *testing.T) {
	target := fakeQuarantineTarget{apply: quarantine.ApplyResult{
		Status: "applied", OperationID: "op-1", StateRef: "state-1", EvidenceRef: "evidence-1", Reason: "drive_object_quarantined",
	}}
	handler := quarantineApplyHandler(target, "secret-token")
	body := `{"operation_id":"op-1","correlation_id":"corr-1","scope":{"resource_type":"drive_file","resource_id":"drive:11111111-1111-1111-1111-111111111111:file:22222222-2222-2222-2222-222222222222"}}`
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/wardveil/quarantine/apply", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"state_ref":"state-1"`) || strings.Contains(strings.ToLower(res.Body.String()), "filename") {
		t.Fatalf("unexpected response body: %s", res.Body.String())
	}
}

func TestQuarantineReadUnknownFailsClosed(t *testing.T) {
	target := fakeQuarantineTarget{read: quarantine.ReadResult{Status: "unknown"}}
	handler := quarantineReadHandler(target, "secret-token")
	body := `{"scope":{"resource_type":"drive_file","resource_id":"drive:11111111-1111-1111-1111-111111111111:file:22222222-2222-2222-2222-222222222222"}}`
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/wardveil/quarantine/read", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", res.Code)
	}
}
