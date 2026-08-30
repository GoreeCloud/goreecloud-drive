package quota

import (
	"context"
	"errors"
	"testing"
)

type memoryRepo struct{ usage Usage }

func (r *memoryRepo) Get(context.Context, string) (Usage, error) { return r.usage, nil }
func (r *memoryRepo) Reserve(_ context.Context, _ string, bytes int64) (Usage, error) {
	if r.usage.LimitBytes != nil && bytes > *r.usage.LimitBytes-r.usage.UsedBytes {
		return Usage{}, ErrExceeded
	}
	r.usage.UsedBytes += bytes
	return r.usage, nil
}
func (r *memoryRepo) Release(_ context.Context, _ string, bytes int64) (Usage, error) {
	r.usage.UsedBytes -= bytes
	if r.usage.UsedBytes < 0 {
		r.usage.UsedBytes = 0
	}
	return r.usage, nil
}

func TestCheckAndReserveBoundedQuota(t *testing.T) {
	limit := int64(10)
	repo := &memoryRepo{usage: Usage{SpaceID: "space", LimitBytes: &limit, UsedBytes: 7}}
	service := New(repo)
	if _, err := service.Check(context.Background(), "space", 3); err != nil {
		t.Fatal(err)
	}
	usage, err := service.Reserve(context.Background(), "space", 3)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsedBytes != 10 {
		t.Fatalf("used=%d", usage.UsedBytes)
	}
	if _, err := service.Reserve(context.Background(), "space", 1); !errors.Is(err, ErrExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckFailsClosedWithoutRepository(t *testing.T) {
	if _, err := New(nil).Check(context.Background(), "space", 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err=%v", err)
	}
}
