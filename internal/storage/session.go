package storage

import (
	"fmt"
	"io"
	"os"
)

// Session describes the durable filesystem state of one resumable upload.
type Session struct {
	SpaceID  string
	UploadID string
	Offset   int64
}

// Session returns the current append offset for a staged upload. A missing
// staging object is treated as a new session at offset zero.
func (l *Local) Session(spaceID, uploadID string) (Session, error) {
	path, err := l.StagingPath(spaceID, uploadID)
	if err != nil {
		return Session{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Session{SpaceID: spaceID, UploadID: uploadID}, nil
		}
		return Session{}, fmt.Errorf("stat upload session: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Session{}, fmt.Errorf("upload session is not a regular file")
	}
	return Session{SpaceID: spaceID, UploadID: uploadID, Offset: info.Size()}, nil
}

// OpenStaging opens a private staged upload for security verification without
// exposing its filesystem path outside the storage boundary.
func (l *Local) OpenStaging(spaceID, uploadID string) (io.ReadCloser, error) {
	path, err := l.StagingPath(spaceID, uploadID)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open staged upload: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat staged upload: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("staged upload is not a regular file")
	}
	return file, nil
}

// AppendStaging appends a bounded chunk only when the caller's expected offset
// matches durable state. This makes retries idempotent and prevents overlapping
// writers from silently corrupting a resumable upload.
func (l *Local) AppendStaging(spaceID, uploadID string, expectedOffset int64, src io.Reader, maxChunkBytes int64) (int64, error) {
	if src == nil {
		return 0, fmt.Errorf("upload source must not be nil")
	}
	if expectedOffset < 0 || maxChunkBytes <= 0 {
		return 0, fmt.Errorf("upload offset and chunk limit are invalid")
	}
	path, err := l.StagingPath(spaceID, uploadID)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
		return 0, fmt.Errorf("create staging scope: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("open upload session: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat upload session: %w", err)
	}
	if info.Size() != expectedOffset {
		return info.Size(), fmt.Errorf("upload offset mismatch: expected %d, durable %d", expectedOffset, info.Size())
	}
	if _, err := file.Seek(expectedOffset, io.SeekStart); err != nil {
		return expectedOffset, fmt.Errorf("seek upload session: %w", err)
	}
	written, err := io.Copy(file, io.LimitReader(src, maxChunkBytes+1))
	if err != nil {
		return expectedOffset, fmt.Errorf("append upload chunk: %w", err)
	}
	if written > maxChunkBytes {
		_ = file.Truncate(expectedOffset)
		return expectedOffset, fmt.Errorf("upload chunk exceeds configured maximum of %d bytes", maxChunkBytes)
	}
	if err := file.Sync(); err != nil {
		return expectedOffset, fmt.Errorf("sync upload chunk: %w", err)
	}
	return expectedOffset + written, nil
}

func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if os.IsPathSeparator(path[i]) {
			return path[:i]
		}
	}
	return "."
}
