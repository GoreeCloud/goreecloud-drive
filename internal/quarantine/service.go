package quarantine

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/GoreeCloud/goreecloud-drive/internal/storage"
)

const ResourceType = "drive_file"

type Scope struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

type ApplyRequest struct {
	OperationID   string `json:"operation_id"`
	CorrelationID string `json:"correlation_id"`
	Scope         Scope  `json:"scope"`
}

type ApplyResult struct {
	Status      string `json:"status"`
	OperationID string `json:"operation_id"`
	StateRef    string `json:"state_ref"`
	EvidenceRef string `json:"evidence_ref"`
	Reason      string `json:"reason"`
}

type ReadRequest struct {
	Scope Scope `json:"scope"`
}

type ReadResult struct {
	Status      string `json:"status"`
	OperationID string `json:"operation_id,omitempty"`
	StateRef    string `json:"state_ref,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

type Store interface {
	ApplyQuarantine(spaceID, nodeID, operationID, correlationID string) (storage.QuarantineState, bool, error)
	ReadQuarantine(spaceID, nodeID string) (storage.QuarantineState, bool, error)
}

type Service struct {
	store Store
}

func New(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Apply(_ context.Context, request ApplyRequest) ApplyResult {
	spaceID, nodeID, ok := parseScope(request.Scope)
	if !ok || s == nil || s.store == nil {
		return ApplyResult{Status: "failed", OperationID: request.OperationID, Reason: "invalid_drive_quarantine_scope"}
	}
	state, alreadyApplied, err := s.store.ApplyQuarantine(spaceID, nodeID, request.OperationID, request.CorrelationID)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrQuarantineConflict):
			return ApplyResult{Status: "failed", OperationID: request.OperationID, Reason: "drive_quarantine_conflict"}
		case errors.Is(err, storage.ErrQuarantineReconciliation):
			return ApplyResult{Status: "unknown", OperationID: request.OperationID, Reason: "drive_quarantine_reconciliation_required"}
		case errors.Is(err, os.ErrNotExist):
			return ApplyResult{Status: "failed", OperationID: request.OperationID, Reason: "drive_object_not_found"}
		default:
			return ApplyResult{Status: "unknown", OperationID: request.OperationID, Reason: "drive_quarantine_storage_error"}
		}
	}
	status := "applied"
	if alreadyApplied {
		status = "already_applied"
	}
	return ApplyResult{
		Status:      status,
		OperationID: state.OperationID,
		StateRef:    state.StateRef,
		EvidenceRef: state.EvidenceRef,
		Reason:      "drive_object_quarantined",
	}
}

func (s *Service) Read(_ context.Context, request ReadRequest) ReadResult {
	spaceID, nodeID, ok := parseScope(request.Scope)
	if !ok || s == nil || s.store == nil {
		return ReadResult{Status: "unknown"}
	}
	state, found, err := s.store.ReadQuarantine(spaceID, nodeID)
	if err != nil {
		return ReadResult{Status: "unknown"}
	}
	if !found {
		return ReadResult{Status: "not_quarantined"}
	}
	return ReadResult{
		Status:      "quarantined",
		OperationID: state.OperationID,
		StateRef:    state.StateRef,
		EvidenceRef: state.EvidenceRef,
	}
}

func parseScope(scope Scope) (string, string, bool) {
	if scope.ResourceType != ResourceType {
		return "", "", false
	}
	parts := strings.Split(scope.ResourceID, ":")
	if len(parts) != 4 || parts[0] != "drive" || parts[2] != "file" || parts[1] == "" || parts[3] == "" {
		return "", "", false
	}
	return parts[1], parts[3], true
}
