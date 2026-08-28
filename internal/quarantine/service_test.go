package quarantine

import (
	"context"
	"errors"
	"testing"

	"github.com/GoreeCloud/goreecloud-drive/internal/storage"
)

const testResourceID = "drive:11111111-1111-1111-1111-111111111111:file:22222222-2222-2222-2222-222222222222"

type fakeStore struct {
	state   storage.QuarantineState
	replay  bool
	applyErr error
	found   bool
	readErr error
}

func (f *fakeStore) ApplyQuarantine(_, _, _, _ string) (storage.QuarantineState, bool, error) {
	return f.state, f.replay, f.applyErr
}

func (f *fakeStore) ReadQuarantine(_, _ string) (storage.QuarantineState, bool, error) {
	return f.state, f.found, f.readErr
}

func TestApplyMapsStorageState(t *testing.T) {
	service := New(&fakeStore{state: storage.QuarantineState{
		OperationID: "op-1", StateRef: "state-1", EvidenceRef: "evidence-1",
	}})
	result := service.Apply(context.Background(), ApplyRequest{
		OperationID: "op-1", CorrelationID: "corr-1",
		Scope: Scope{ResourceType: ResourceType, ResourceID: testResourceID},
	})
	if result.Status != "applied" || result.StateRef != "state-1" || result.EvidenceRef != "evidence-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestApplyFailsClosedOnReconciliation(t *testing.T) {
	service := New(&fakeStore{applyErr: storage.ErrQuarantineReconciliation})
	result := service.Apply(context.Background(), ApplyRequest{
		OperationID: "op-1", CorrelationID: "corr-1",
		Scope: Scope{ResourceType: ResourceType, ResourceID: testResourceID},
	})
	if result.Status != "unknown" || result.Reason != "drive_quarantine_reconciliation_required" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestApplyRejectsNonDriveScope(t *testing.T) {
	service := New(&fakeStore{})
	result := service.Apply(context.Background(), ApplyRequest{
		OperationID: "op-1", CorrelationID: "corr-1",
		Scope: Scope{ResourceType: "mail_attachment", ResourceID: testResourceID},
	})
	if result.Status != "failed" || result.Reason != "invalid_drive_quarantine_scope" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestReadMapsNotQuarantined(t *testing.T) {
	service := New(&fakeStore{found: false})
	result := service.Read(context.Background(), ReadRequest{Scope: Scope{ResourceType: ResourceType, ResourceID: testResourceID}})
	if result.Status != "not_quarantined" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestReadFailsClosedOnStorageError(t *testing.T) {
	service := New(&fakeStore{readErr: errors.New("boom")})
	result := service.Read(context.Background(), ReadRequest{Scope: Scope{ResourceType: ResourceType, ResourceID: testResourceID}})
	if result.Status != "unknown" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
