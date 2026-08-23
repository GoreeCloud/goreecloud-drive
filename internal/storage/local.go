// Package storage defines the initial filesystem storage boundary.
package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// Local is a development storage backend. Finalized payloads and upload staging
// remain deliberately separated so later resumable-transfer work can finalize
// files atomically.
type Local struct {
	root string
}

// NewLocal validates a configured storage root.
func NewLocal(root string) (*Local, error) {
	if root == "" {
		return nil, fmt.Errorf("storage root must not be empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve storage root: %w", err)
	}
	return &Local{root: absolute}, nil
}

// EnsureLayout creates private runtime directories. These directories are not a
// substitute for the approved TrueNAS dataset layout used by future deployments.
func (l *Local) EnsureLayout() error {
	for _, name := range []string{"objects", "staging", "trash"} {
		if err := os.MkdirAll(filepath.Join(l.root, name), 0o700); err != nil {
			return fmt.Errorf("create %s directory: %w", name, err)
		}
	}
	return nil
}
