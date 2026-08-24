// Package storage defines the initial filesystem storage boundary.
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Local is a development storage backend. Finalized payloads and upload staging
// remain deliberately separated so later resumable-transfer work can finalize
// files atomically.
type Local struct {
	root string
}

// NewLocal validates a configured storage root.
func NewLocal(root string) (*Local, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("storage root must not be empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve storage root: %w", err)
	}
	return &Local{root: filepath.Clean(absolute)}, nil
}

// EnsureLayout creates private runtime directories. These directories are not a
// substitute for the approved TrueNAS dataset layout used by future deployments.
func (l *Local) EnsureLayout() error {
	if l == nil || l.root == "" {
		return fmt.Errorf("storage backend is unavailable")
	}
	for _, name := range []string{"objects", "staging", "trash"} {
		if err := os.MkdirAll(filepath.Join(l.root, name), 0o700); err != nil {
			return fmt.Errorf("create %s directory: %w", name, err)
		}
	}
	return nil
}

// ObjectPath returns the private finalized-content path for a stable Space/node
// identifier pair. User-controlled filenames are intentionally excluded from
// physical storage paths so rename operations cannot create traversal hazards.
func (l *Local) ObjectPath(spaceID, nodeID string) (string, error) {
	return l.scopedPath("objects", spaceID, nodeID)
}

// StagingPath returns the private path for an upload session. Staging objects
// remain separate from finalized content until a later atomic-finalization step.
func (l *Local) StagingPath(spaceID, uploadID string) (string, error) {
	return l.scopedPath("staging", spaceID, uploadID)
}

// TrashPath returns the private path used when payload content is moved out of
// the active object namespace while metadata remains recoverable.
func (l *Local) TrashPath(spaceID, nodeID string) (string, error) {
	return l.scopedPath("trash", spaceID, nodeID)
}

func (l *Local) scopedPath(area, scopeID, objectID string) (string, error) {
	if l == nil || l.root == "" {
		return "", fmt.Errorf("storage backend is unavailable")
	}
	if !validStorageID(scopeID) || !validStorageID(objectID) {
		return "", fmt.Errorf("storage identifiers must be canonical UUIDs")
	}
	path := filepath.Join(l.root, area, scopeID, objectID)
	base := filepath.Join(l.root, area)
	relative, err := filepath.Rel(base, path)
	if err != nil {
		return "", fmt.Errorf("resolve storage path: %w", err)
	}
	if relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("storage path escaped configured boundary")
	}
	return path, nil
}

func validStorageID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				return false
			}
		}
	}
	return true
}
