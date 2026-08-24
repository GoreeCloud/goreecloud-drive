package storage

import (
	"os"
	"path/filepath"
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

func TestNilLocalFailsClosed(t *testing.T) {
	var store *Local
	if err := store.EnsureLayout(); err == nil {
		t.Fatal("EnsureLayout() unexpectedly succeeded")
	}
	if _, err := store.ObjectPath(testSpaceID, testNodeID); err == nil {
		t.Fatal("ObjectPath() unexpectedly succeeded")
	}
}
