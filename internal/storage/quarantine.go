package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrQuarantineConflict       = errors.New("quarantine operation conflicts with existing state")
	ErrQuarantineReconciliation = errors.New("quarantine state requires reconciliation")
)

// QuarantineState is Drive's authoritative local record for one quarantined
// object. It intentionally contains stable internal identifiers and operation
// provenance only; user-facing filenames and raw content never belong here.
type QuarantineState struct {
	SpaceID       string `json:"space_id"`
	NodeID        string `json:"node_id"`
	OperationID   string `json:"operation_id"`
	CorrelationID string `json:"correlation_id"`
	Status        string `json:"status"`
	StateRef      string `json:"state_ref"`
	EvidenceRef   string `json:"evidence_ref"`
	ObservedAt    string `json:"observed_at"`
}

// QuarantinePath returns the private payload path used for isolated content.
func (l *Local) QuarantinePath(spaceID, nodeID string) (string, error) {
	return l.scopedPath("quarantine", spaceID, nodeID)
}

// QuarantineStatePath returns the private operation-state path for a node.
func (l *Local) QuarantineStatePath(spaceID, nodeID string) (string, error) {
	return l.scopedPath("quarantine-state", spaceID, nodeID)
}

// ApplyQuarantine atomically removes a finalized object from the active object
// namespace while preserving the payload in the private quarantine namespace.
// A durable pending state is recorded before the side effect so an interrupted
// operation can be reconciled without blindly replaying a conflicting action.
func (l *Local) ApplyQuarantine(spaceID, nodeID, operationID, correlationID string) (QuarantineState, bool, error) {
	if !validOperationID(operationID) || !validOperationID(correlationID) {
		return QuarantineState{}, false, fmt.Errorf("quarantine operation identifiers are invalid")
	}
	object, err := l.ObjectPath(spaceID, nodeID)
	if err != nil {
		return QuarantineState{}, false, err
	}
	quarantine, err := l.QuarantinePath(spaceID, nodeID)
	if err != nil {
		return QuarantineState{}, false, err
	}
	statePath, err := l.QuarantineStatePath(spaceID, nodeID)
	if err != nil {
		return QuarantineState{}, false, err
	}
	if err := os.MkdirAll(filepath.Dir(quarantine), 0o700); err != nil {
		return QuarantineState{}, false, fmt.Errorf("create quarantine scope: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return QuarantineState{}, false, fmt.Errorf("create quarantine state scope: %w", err)
	}

	state, found, err := readQuarantineState(statePath)
	if err != nil {
		return QuarantineState{}, false, err
	}
	if found {
		if state.OperationID != operationID || state.CorrelationID != correlationID {
			return QuarantineState{}, false, ErrQuarantineConflict
		}
		return l.reconcileQuarantine(object, quarantine, statePath, state)
	}

	if exists(quarantine) {
		return QuarantineState{}, false, ErrQuarantineReconciliation
	}
	if !exists(object) {
		return QuarantineState{}, false, os.ErrNotExist
	}

	state = QuarantineState{
		SpaceID:       spaceID,
		NodeID:        nodeID,
		OperationID:   operationID,
		CorrelationID: correlationID,
		Status:        "pending",
		StateRef:      "drive-quarantine:" + spaceID + ":" + nodeID,
		EvidenceRef:   "drive-quarantine-operation:" + operationID,
		ObservedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeQuarantineStateExclusive(statePath, state); err != nil {
		if errors.Is(err, os.ErrExist) {
			state, found, readErr := readQuarantineState(statePath)
			if readErr != nil || !found {
				return QuarantineState{}, false, ErrQuarantineReconciliation
			}
			if state.OperationID != operationID || state.CorrelationID != correlationID {
				return QuarantineState{}, false, ErrQuarantineConflict
			}
			return l.reconcileQuarantine(object, quarantine, statePath, state)
		}
		return QuarantineState{}, false, err
	}
	return l.reconcileQuarantine(object, quarantine, statePath, state)
}

// ReadQuarantine returns the authoritative Drive quarantine state for a node.
// Payload/state disagreement is treated as reconciliation-required rather than
// silently reporting a favorable state.
func (l *Local) ReadQuarantine(spaceID, nodeID string) (QuarantineState, bool, error) {
	object, err := l.ObjectPath(spaceID, nodeID)
	if err != nil {
		return QuarantineState{}, false, err
	}
	quarantine, err := l.QuarantinePath(spaceID, nodeID)
	if err != nil {
		return QuarantineState{}, false, err
	}
	statePath, err := l.QuarantineStatePath(spaceID, nodeID)
	if err != nil {
		return QuarantineState{}, false, err
	}
	state, found, err := readQuarantineState(statePath)
	if err != nil {
		return QuarantineState{}, false, err
	}
	if !found {
		if exists(quarantine) {
			return QuarantineState{}, false, ErrQuarantineReconciliation
		}
		return QuarantineState{}, false, nil
	}
	if state.Status != "quarantined" || !exists(quarantine) || exists(object) {
		return QuarantineState{}, false, ErrQuarantineReconciliation
	}
	return state, true, nil
}

func (l *Local) reconcileQuarantine(object, quarantine, statePath string, state QuarantineState) (QuarantineState, bool, error) {
	objectExists := exists(object)
	quarantineExists := exists(quarantine)
	if state.Status == "quarantined" {
		if !quarantineExists || objectExists {
			return QuarantineState{}, false, ErrQuarantineReconciliation
		}
		return state, true, nil
	}
	if state.Status != "pending" {
		return QuarantineState{}, false, ErrQuarantineReconciliation
	}

	if !quarantineExists {
		if !objectExists {
			return QuarantineState{}, false, ErrQuarantineReconciliation
		}
		if err := os.Link(object, quarantine); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return QuarantineState{}, false, fmt.Errorf("publish quarantine payload: %w", err)
			}
		}
		quarantineExists = true
	}
	if !quarantineExists {
		return QuarantineState{}, false, ErrQuarantineReconciliation
	}
	if objectExists {
		if err := os.Remove(object); err != nil {
			return QuarantineState{}, false, fmt.Errorf("remove active object after quarantine publish: %w", err)
		}
	}

	state.Status = "quarantined"
	state.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := writeQuarantineStateAtomic(statePath, state); err != nil {
		return QuarantineState{}, false, fmt.Errorf("finalize quarantine state: %w", err)
	}
	return state, false, nil
}

func readQuarantineState(path string) (QuarantineState, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return QuarantineState{}, false, nil
		}
		return QuarantineState{}, false, fmt.Errorf("read quarantine state: %w", err)
	}
	var state QuarantineState
	if err := json.Unmarshal(data, &state); err != nil {
		return QuarantineState{}, false, ErrQuarantineReconciliation
	}
	if state.SpaceID == "" || state.NodeID == "" || state.OperationID == "" || state.CorrelationID == "" || state.StateRef == "" || state.EvidenceRef == "" {
		return QuarantineState{}, false, ErrQuarantineReconciliation
	}
	return state, true, nil
}

func writeQuarantineStateExclusive(path string, state QuarantineState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode quarantine state: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write quarantine state: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync quarantine state: %w", err)
	}
	return file.Close()
}

func writeQuarantineStateAtomic(path string, state QuarantineState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode quarantine state: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".quarantine-state-*")
	if err != nil {
		return fmt.Errorf("create quarantine state temporary file: %w", err)
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func validOperationID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 160 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-_.:", r) {
			continue
		}
		return false
	}
	return true
}
