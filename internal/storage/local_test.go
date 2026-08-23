package storage

import (
	"os"
	"path/filepath"
	"testing"
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
