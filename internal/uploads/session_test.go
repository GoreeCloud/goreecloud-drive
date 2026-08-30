package uploads

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/GoreeCloud/goreecloud-drive/internal/wardveil"
)

type fakeStore struct {
	offset    int64
	content   []byte
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
	f.content = append(f.content, body...)
	f.offset += int64(len(body))
	return f.offset, nil
}

func (f *fakeStore) OpenStaging(_, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.content)), nil
}

func (f *fakeStore) Finalize(_, _, _ string) error {
	f.finalized = true
	return nil
}

type fakeSecurityGate struct {
	decision wardveil.Decision
	err      error
}

func (g fakeSecurityGate) EvaluateUpload(context.Context, string, string, string) (wardveil.Decision, error) {
	return g.decision, g.err
}

func allowGate() SecurityGate {
	return fakeSecurityGate{decision: wardveil.Decision{Disposition: wardveil.DispositionAllow, CanRelease: true}}
}

func createAssignedSession(t *testing.T, service Service, repo Repository) Session {
	t.Helper()
	session, err := service.Create(context.Background(), "acct", "space", "", "report.pdf")
	if err != nil {
		t.Fatal(err)
	}
	session.NodeID = "node"
	if err := repo.Update(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	return session
}

func TestServiceCreatePreservesDestinationIntent(t *testing.T) {
	repo := NewMemoryRepository()
	service := New(repo, &fakeStore{}, allowGate(), 8, time.Hour)
	session, err := service.Create(context.Background(), "acct", "space", "parent", "report.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if session.ParentNodeID != "parent" || session.TargetName != "report.pdf" || session.NodeID != "" {
		t.Fatalf("unexpected target model: %+v", session)
	}
	stored, err := repo.Get(context.Background(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ParentNodeID != "parent" || stored.TargetName != "report.pdf" {
		t.Fatalf("stored target model: %+v", stored)
	}
}

func TestServiceCreateRejectsUnsafeTargetNames(t *testing.T) {
	service := New(NewMemoryRepository(), &fakeStore{}, allowGate(), 8, time.Hour)
	for _, name := range []string{"", ".", "..", "folder/file", `folder\file`} {
		if _, err := service.Create(context.Background(), "acct", "space", "", name); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("name=%q err=%v", name, err)
		}
	}
}

func TestServiceAppendAndCompleteAfterWardveilAllowsRelease(t *testing.T) {
	repo := NewMemoryRepository()
	store := &fakeStore{}
	service := New(repo, store, allowGate(), 8, time.Hour)
	ctx := context.Background()
	session := createAssignedSession(t, service, repo)
	updated, err := service.Append(ctx, "acct", "space", session.ID, 0, bytes.NewBufferString("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Offset != 5 {
		t.Fatalf("offset=%d want 5", updated.Offset)
	}
	completed, err := service.Complete(ctx, "acct", "space", session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StateCompleted || !store.finalized {
		t.Fatal("expected completed finalized session")
	}
}

func TestServiceCompleteRequiresAssignedFinalNode(t *testing.T) {
	repo := NewMemoryRepository()
	store := &fakeStore{}
	service := New(repo, store, allowGate(), 8, time.Hour)
	session, err := service.Create(context.Background(), "acct", "space", "", "report.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), "acct", "space", session.ID); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("err=%v", err)
	}
	if store.finalized {
		t.Fatal("unassigned upload must not be finalized")
	}
}

func TestServiceCompleteFailsClosedWithoutSecurityGate(t *testing.T) {
	repo := NewMemoryRepository()
	store := &fakeStore{}
	service := New(repo, store, nil, 8, time.Hour)
	session := createAssignedSession(t, service, repo)
	if _, err := service.Complete(context.Background(), "acct", "space", session.ID); !errors.Is(err, ErrSecurityUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if store.finalized {
		t.Fatal("security-unverified upload must not be finalized")
	}
}

func TestServiceCompleteBlocksWardveilDeniedRelease(t *testing.T) {
	repo := NewMemoryRepository()
	store := &fakeStore{}
	gate := fakeSecurityGate{decision: wardveil.Decision{Disposition: wardveil.DispositionBlockQuarantine, QuarantineRequired: true, ReasonCodes: []string{"wardveil_malicious_digest_match"}}}
	service := New(repo, store, gate, 8, time.Hour)
	session := createAssignedSession(t, service, repo)
	if _, err := service.Complete(context.Background(), "acct", "space", session.ID); !errors.Is(err, ErrSecurityBlocked) {
		t.Fatalf("err=%v", err)
	}
	if store.finalized {
		t.Fatal("blocked upload must remain outside active object namespace")
	}
}

func TestServiceCompleteFailsClosedWhenScannerUnavailable(t *testing.T) {
	repo := NewMemoryRepository()
	store := &fakeStore{}
	service := New(repo, store, fakeSecurityGate{err: errors.New("Wardveil unavailable")}, 8, time.Hour)
	session := createAssignedSession(t, service, repo)
	if _, err := service.Complete(context.Background(), "acct", "space", session.ID); !errors.Is(err, ErrSecurityUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if store.finalized {
		t.Fatal("upload must not be finalized when Wardveil is unavailable")
	}
}

func TestServiceRejectsWrongOffsetAndOwner(t *testing.T) {
	repo := NewMemoryRepository()
	service := New(repo, &fakeStore{}, allowGate(), 8, time.Hour)
	ctx := context.Background()
	session, err := service.Create(ctx, "acct", "space", "", "report.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(ctx, "acct", "space", session.ID, 1, bytes.NewBufferString("x")); err != ErrOffsetMismatch {
		t.Fatalf("err=%v", err)
	}
	if _, err := service.Get(ctx, "other", "space", session.ID); err != ErrForbidden {
		t.Fatalf("err=%v", err)
	}
}
