// Package storage defines the initial filesystem storage boundary.
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Local is a development storage backend. Finalized payloads and upload staging
// remain deliberately separated so resumable-transfer work can safely build on
// an atomic finalization boundary.
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
// remain separate from finalized content until an atomic finalization step.
func (l *Local) StagingPath(spaceID, uploadID string) (string, error) {
	return l.scopedPath("staging", spaceID, uploadID)
}

// TrashPath returns the private path used when payload content is moved out of
// the active object namespace while metadata remains recoverable.
func (l *Local) TrashPath(spaceID, nodeID string) (string, error) {
	return l.scopedPath("trash", spaceID, nodeID)
}

// WriteStaging writes a complete upload body into the staging namespace.
// The body is first written to a private temporary file in the same directory,
// synced, and then renamed into place so a partial write is never exposed as a
// complete staging object. maxBytes must be positive.
func (l *Local) WriteStaging(spaceID, uploadID string, src io.Reader, maxBytes int64) (int64, string, error) {
	if src == nil {
		return 0, "", fmt.Errorf("upload source must not be nil")
	}
	if maxBytes <= 0 {
		return 0, "", fmt.Errorf("maximum upload size must be positive")
	}
	path, err := l.StagingPath(spaceID, uploadID)
	if err != nil {
		return 0, "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, "", fmt.Errorf("create staging scope: %w", err)
	}

	temp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return 0, "", fmt.Errorf("create staging temporary file: %w", err)
	}
	tempName := temp.Name()
	keepTemp := true
	defer func() {
		_ = temp.Close()
		if keepTemp {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return 0, "", fmt.Errorf("secure staging temporary file: %w", err)
	}

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temp, hash), io.LimitReader(src, maxBytes+1))
	if err != nil {
		return 0, "", fmt.Errorf("write staging object: %w", err)
	}
	if written > maxBytes {
		return 0, "", fmt.Errorf("upload exceeds configured maximum of %d bytes", maxBytes)
	}
	if err := temp.Sync(); err != nil {
		return 0, "", fmt.Errorf("sync staging object: %w", err)
	}
	if err := temp.Close(); err != nil {
		return 0, "", fmt.Errorf("close staging object: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return 0, "", fmt.Errorf("publish staging object: %w", err)
	}
	keepTemp = false
	return written, hex.EncodeToString(hash.Sum(nil)), nil
}

// Finalize installs a staging payload into the finalized object namespace.
// A hard link provides an atomic no-overwrite publish operation within the
// configured storage root. Existing finalized content is never replaced.
func (l *Local) Finalize(spaceID, uploadID, nodeID string) error {
	staging, err := l.StagingPath(spaceID, uploadID)
	if err != nil {
		return err
	}
	object, err := l.ObjectPath(spaceID, nodeID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(object), 0o700); err != nil {
		return fmt.Errorf("create object scope: %w", err)
	}
	if err := os.Link(staging, object); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("finalized object already exists")
		}
		return fmt.Errorf("publish finalized object: %w", err)
	}
	if err := os.Remove(staging); err != nil {
		return fmt.Errorf("remove finalized staging object: %w", err)
	}
	return nil
}

// OpenObject opens finalized content for reading without exposing its physical
// path to callers.
func (l *Local) OpenObject(spaceID, nodeID string) (*os.File, error) {
	path, err := l.ObjectPath(spaceID, nodeID)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open finalized object: %w", err)
	}
	return file, nil
}

// MoveToTrash atomically removes an active object from the object namespace
// without overwriting an existing trash payload for the same stable node ID.
func (l *Local) MoveToTrash(spaceID, nodeID string) error {
	object, err := l.ObjectPath(spaceID, nodeID)
	if err != nil {
		return err
	}
	trash, err := l.TrashPath(spaceID, nodeID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(trash), 0o700); err != nil {
		return fmt.Errorf("create trash scope: %w", err)
	}
	if err := os.Link(object, trash); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("trash object already exists")
		}
		return fmt.Errorf("publish trash object: %w", err)
	}
	if err := os.Remove(object); err != nil {
		return fmt.Errorf("remove active object after trash publish: %w", err)
	}
	return nil
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
