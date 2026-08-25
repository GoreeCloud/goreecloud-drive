package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testSpaceID  = "11111111-1111-4111-8111-111111111111"
	testNodeID   = "22222222-2222-4222-8222-222222222222"
	testUploadID = "33333333-3333-4333-8333-333333333333"
)

func TestEnsureLayoutCreatesExpectedDirectories(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocal(root)
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}
	if err := store.EnsureLayout(); err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}
	for _, name := range []string{"objects", "staging", "trash"} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", name)
		}
	}
}

func TestStableIdentifierPathsStayInsideStorageAreas(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocal(root)
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}

	tests := []struct {
		name string
		got  func() (string, error)
		want string
	}{
		{name: "object", got: func() (string, error) { return store.ObjectPath(testSpaceID, testNodeID) }, want: filepath.Join(root, "objects", testSpaceID, testNodeID)},
		{name: "staging", got: func() (string, error) { return store.StagingPath(testSpaceID, testUploadID) }, want: filepath.Join(root, "staging", testSpaceID, testUploadID)},
		{name: "trash", got: func() (string, error) { return store.TrashPath(testSpaceID, testNodeID) }, want: filepath.Join(root, "trash", testSpaceID, testNodeID)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.got()
			if err != nil {
				t.Fatalf("path error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStableIdentifierPathsRejectTraversalAndNonCanonicalIDs(t *testing.T) {
	store, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}

	invalid := []string{
		"../escape",
		"11111111-1111-4111-8111-11111111111G",
		"11111111-1111-4111-8111-111111111111/extra",
		"11111111111141118111111111111111",
		"",
	}
	for _, value := range invalid {
		if _, err := store.ObjectPath(value, testNodeID); err == nil {
			t.Fatalf("ObjectPath(%q, valid) unexpectedly succeeded", value)
		}
		if _, err := store.ObjectPath(testSpaceID, value); err == nil {
			t.Fatalf("ObjectPath(valid, %q) unexpectedly succeeded", value)
		}
	}
}

func TestWriteFinalizeReadAndTrashLifecycle(t *testing.T) {
	store, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}
	if err := store.EnsureLayout(); err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}

	payload := "GoreeCloud Drive atomic payload"
	written, checksum, err := store.WriteStaging(testSpaceID, testUploadID, strings.NewReader(payload), 1024)
	if err != nil {
		t.Fatalf("WriteStaging() error = %v", err)
	}
	if written != int64(len(payload)) {
		t.Fatalf("WriteStaging() bytes = %d, want %d", written, len(payload))
	}
	digest := sha256.Sum256([]byte(payload))
	if checksum != hex.EncodeToString(digest[:]) {
		t.Fatalf("WriteStaging() checksum = %q", checksum)
	}

	if err := store.Finalize(testSpaceID, testUploadID, testNodeID); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	staging, _ := store.StagingPath(testSpaceID, testUploadID)
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("staging object still exists or stat failed: %v", err)
	}

	file, err := store.OpenObject(testSpaceID, testNodeID)
	if err != nil {
		t.Fatalf("OpenObject() error = %v", err)
	}
	got, err := io.ReadAll(file)
	_ = file.Close()
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("object payload = %q, want %q", got, payload)
	}

	if err := store.MoveToTrash(testSpaceID, testNodeID); err != nil {
		t.Fatalf("MoveToTrash() error = %v", err)
	}
	object, _ := store.ObjectPath(testSpaceID, testNodeID)
	if _, err := os.Stat(object); !os.IsNotExist(err) {
		t.Fatalf("active object still exists or stat failed: %v", err)
	}
	trash, _ := store.TrashPath(testSpaceID, testNodeID)
	content, err := os.ReadFile(trash)
	if err != nil {
		t.Fatalf("read trash object: %v", err)
	}
	if string(content) != payload {
		t.Fatalf("trash payload = %q, want %q", content, payload)
	}
}

func TestWriteStagingRejectsOversizeAndDoesNotPublishPartialObject(t *testing.T) {
	store, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}
	if _, _, err := store.WriteStaging(testSpaceID, testUploadID, strings.NewReader("too large"), 3); err == nil {
		t.Fatal("WriteStaging() unexpectedly accepted oversized payload")
	}
	path, _ := store.StagingPath(testSpaceID, testUploadID)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("oversized staging path exists or stat failed: %v", err)
	}
}

func TestFinalizeRefusesToOverwriteExistingObject(t *testing.T) {
	store, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocal() error = %v", err)
	}
	if err := store.EnsureLayout(); err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}
	object, _ := store.ObjectPath(testSpaceID, testNodeID)
	if err := os.MkdirAll(filepath.Dir(object), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(object, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.WriteStaging(testSpaceID, testUploadID, strings.NewReader("new"), 1024); err != nil {
		t.Fatalf("WriteStaging() error = %v", err)
	}
	if err := store.Finalize(testSpaceID, testUploadID, testNodeID); err == nil {
		t.Fatal("Finalize() unexpectedly overwrote existing object")
	}
	got, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing" {
		t.Fatalf("existing object changed to %q", got)
	}
}

func TestNilLocalFailsClosed(t *testing.T) {
	var store *Local
	if err := store.EnsureLayout(); err == nil {
		t.Fatal("EnsureLayout() unexpectedly succeeded")
	}
	if _, err := store.ObjectPath(testSpaceID, testNodeID); err == nil {
		t.Fatal("ObjectPath() unexpectedly succeeded")
	}
	if _, _, err := store.WriteStaging(testSpaceID, testUploadID, strings.NewReader("x"), 1); err == nil {
		t.Fatal("WriteStaging() unexpectedly succeeded")
	}
}
