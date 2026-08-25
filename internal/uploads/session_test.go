package uploads

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

type fakeStore struct {
	offset int64
	finalized bool
}

func (f *fakeStore) AppendStaging(_, _ string, expectedOffset int64, src io.Reader, maxChunkBytes int64) (int64, error) {
	if expectedOffset != f.offset {
		return f.offset, ErrOffsetMismatch
	}
	body, _ := io.ReadAll(io.LimitReader(src, maxChunkBytes+1))
	if int64(len(body)) > maxChunkBytes {
		return f.offset, io.ErrShortBuffer
	}
	f.offset += int64(len(body))
	return f.offset, nil
}

func (f *fakeStore) Finalize(_, _, _ string) error {
	f.finalized = true
	return nil
}

func TestServiceAppendAndComplete(t *testing.T) {
	repo := NewMemoryRepository()
	store := &fakeStore{}
	service := New(repo, store, 8, time.Hour)
	ctx := context.Background()
	session, err := service.Create(ctx, "acct", "space", "node")
	if err != nil { t.Fatal(err) }
	updated, err := service.Append(ctx, "acct", "space", session.ID, 0, bytes.NewBufferString("hello"))
	if err != nil { t.Fatal(err) }
	if updated.Offset != 5 { t.Fatalf("offset=%d want 5", updated.Offset) }
	completed, err := service.Complete(ctx, "acct", "space", session.ID)
	if err != nil { t.Fatal(err) }
	if completed.State != StateCompleted || !store.finalized { t.Fatal("expected completed finalized session") }
}

func TestServiceRejectsWrongOffsetAndOwner(t *testing.T) {
	repo := NewMemoryRepository()
	service := New(repo, &fakeStore{}, 8, time.Hour)
	ctx := context.Background()
	session, err := service.Create(ctx, "acct", "space", "node")
	if err != nil { t.Fatal(err) }
	if _, err := service.Append(ctx, "acct", "space", session.ID, 1, bytes.NewBufferString("x")); err != ErrOffsetMismatch { t.Fatalf("err=%v", err) }
	if _, err := service.Get(ctx, "other", "space", session.ID); err != ErrForbidden { t.Fatalf("err=%v", err) }
}
