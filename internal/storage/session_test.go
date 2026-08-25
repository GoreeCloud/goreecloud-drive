package storage

import (
	"strings"
	"testing"
)

func TestAppendStagingResumesAtDurableOffset(t *testing.T) {
	store, err := NewLocal(t.TempDir())
	if err != nil { t.Fatal(err) }
	space := "11111111-1111-1111-1111-111111111111"
	upload := "22222222-2222-2222-2222-222222222222"

	next, err := store.AppendStaging(space, upload, 0, strings.NewReader("hello "), 16)
	if err != nil { t.Fatal(err) }
	if next != 6 { t.Fatalf("offset=%d want 6", next) }
	next, err = store.AppendStaging(space, upload, next, strings.NewReader("world"), 16)
	if err != nil { t.Fatal(err) }
	if next != 11 { t.Fatalf("offset=%d want 11", next) }

	session, err := store.Session(space, upload)
	if err != nil { t.Fatal(err) }
	if session.Offset != 11 { t.Fatalf("durable offset=%d want 11", session.Offset) }
}

func TestAppendStagingRejectsOffsetMismatch(t *testing.T) {
	store, _ := NewLocal(t.TempDir())
	space := "11111111-1111-1111-1111-111111111111"
	upload := "22222222-2222-2222-2222-222222222222"
	if _, err := store.AppendStaging(space, upload, 0, strings.NewReader("abc"), 8); err != nil { t.Fatal(err) }
	durable, err := store.AppendStaging(space, upload, 1, strings.NewReader("x"), 8)
	if err == nil { t.Fatal("expected offset mismatch") }
	if durable != 3 { t.Fatalf("durable offset=%d want 3", durable) }
}

func TestAppendStagingRollsBackOversizedChunk(t *testing.T) {
	store, _ := NewLocal(t.TempDir())
	space := "11111111-1111-1111-1111-111111111111"
	upload := "22222222-2222-2222-2222-222222222222"
	if _, err := store.AppendStaging(space, upload, 0, strings.NewReader("toolong"), 3); err == nil { t.Fatal("expected chunk limit error") }
	session, err := store.Session(space, upload)
	if err != nil { t.Fatal(err) }
	if session.Offset != 0 { t.Fatalf("offset=%d want 0", session.Offset) }
}
