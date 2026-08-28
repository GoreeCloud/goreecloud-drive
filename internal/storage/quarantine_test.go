package storage

import (
	"errors"
	"os"
	"strings"
	"testing"
)

const (
	quarantineSpaceID = "11111111-1111-1111-1111-111111111111"
	quarantineNodeID  = "22222222-2222-2222-2222-222222222222"
	quarantineUpload  = "33333333-3333-3333-3333-333333333333"
)

func TestApplyQuarantineMovesObjectAndSupportsExactReplay(t *testing.T) {
	store := newQuarantineTestStore(t)
	writeQuarantineTestObject(t, store, "payload")

	state, replay, err := store.ApplyQuarantine(quarantineSpaceID, quarantineNodeID, "op-123", "corr-123")
	if err != nil {
		t.Fatalf("apply quarantine: %v", err)
	}
	if replay {
		t.Fatal("first application must not be reported as replay")
	}
	if state.Status != "quarantined" || state.OperationID != "op-123" {
		t.Fatalf("unexpected state: %+v", state)
	}
	objectPath, _ := store.ObjectPath(quarantineSpaceID, quarantineNodeID)
	if _, err := os.Stat(objectPath); !os.IsNotExist(err) {
		t.Fatalf("active object must be absent after quarantine, err=%v", err)
	}
	quarantinePath, _ := store.QuarantinePath(quarantineSpaceID, quarantineNodeID)
	data, err := os.ReadFile(quarantinePath)
	if err != nil || string(data) != "payload" {
		t.Fatalf("quarantine payload mismatch: %q err=%v", data, err)
	}

	replayed, replay, err := store.ApplyQuarantine(quarantineSpaceID, quarantineNodeID, "op-123", "corr-123")
	if err != nil || !replay {
		t.Fatalf("exact replay must be idempotent, replay=%v err=%v", replay, err)
	}
	if replayed.StateRef != state.StateRef || replayed.EvidenceRef != state.EvidenceRef {
		t.Fatal("exact replay changed stable quarantine provenance")
	}
}

func TestApplyQuarantineRejectsConflictingOperation(t *testing.T) {
	store := newQuarantineTestStore(t)
	writeQuarantineTestObject(t, store, "payload")
	if _, _, err := store.ApplyQuarantine(quarantineSpaceID, quarantineNodeID, "op-123", "corr-123"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyQuarantine(quarantineSpaceID, quarantineNodeID, "op-456", "corr-456"); !errors.Is(err, ErrQuarantineConflict) {
		t.Fatalf("expected quarantine conflict, got %v", err)
	}
}

func TestReadQuarantineFailsClosedOnPayloadStateMismatch(t *testing.T) {
	store := newQuarantineTestStore(t)
	writeQuarantineTestObject(t, store, "payload")
	if _, _, err := store.ApplyQuarantine(quarantineSpaceID, quarantineNodeID, "op-123", "corr-123"); err != nil {
		t.Fatal(err)
	}
	quarantinePath, _ := store.QuarantinePath(quarantineSpaceID, quarantineNodeID)
	if err := os.Remove(quarantinePath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReadQuarantine(quarantineSpaceID, quarantineNodeID); !errors.Is(err, ErrQuarantineReconciliation) {
		t.Fatalf("expected reconciliation-required read, got %v", err)
	}
}

func TestQuarantineStateExcludesUserFacingNames(t *testing.T) {
	store := newQuarantineTestStore(t)
	writeQuarantineTestObject(t, store, "payload")
	if _, _, err := store.ApplyQuarantine(quarantineSpaceID, quarantineNodeID, "op-123", "corr-123"); err != nil {
		t.Fatal(err)
	}
	statePath, _ := store.QuarantineStatePath(quarantineSpaceID, quarantineNodeID)
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"filename", "url", "token", "payload"} {
		if strings.Contains(strings.ToLower(string(data)), prohibited) {
			t.Fatalf("quarantine state leaked prohibited field %q: %s", prohibited, data)
		}
	}
}

func newQuarantineTestStore(t *testing.T) *Local {
	t.Helper()
	store, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	return store
}

func writeQuarantineTestObject(t *testing.T, store *Local, body string) {
	t.Helper()
	if _, _, err := store.WriteStaging(quarantineSpaceID, quarantineUpload, strings.NewReader(body), 1024); err != nil {
		t.Fatal(err)
	}
	if err := store.Finalize(quarantineSpaceID, quarantineUpload, quarantineNodeID); err != nil {
		t.Fatal(err)
	}
}
