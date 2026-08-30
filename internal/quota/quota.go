package quota

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrUnavailable = errors.New("quota service unavailable")
	ErrExceeded    = errors.New("quota exceeded")
	ErrInvalidSize = errors.New("quota size must be positive")
)

type Usage struct {
	SpaceID    string
	LimitBytes *int64
	UsedBytes  int64
}

type Repository interface {
	Get(context.Context, string) (Usage, error)
	Reserve(context.Context, string, int64) (Usage, error)
	Release(context.Context, string, int64) (Usage, error)
}

type Service struct {
	repo Repository
}

func New(repo Repository) Service { return Service{repo: repo} }

func (s Service) Check(ctx context.Context, spaceID string, additionalBytes int64) (Usage, error) {
	if s.repo == nil || spaceID == "" {
		return Usage{}, ErrUnavailable
	}
	if additionalBytes <= 0 {
		return Usage{}, ErrInvalidSize
	}
	usage, err := s.repo.Get(ctx, spaceID)
	if err != nil {
		return Usage{}, err
	}
	if usage.LimitBytes != nil && additionalBytes > *usage.LimitBytes-usage.UsedBytes {
		return usage, ErrExceeded
	}
	return usage, nil
}

func (s Service) Reserve(ctx context.Context, spaceID string, bytes int64) (Usage, error) {
	if s.repo == nil || spaceID == "" {
		return Usage{}, ErrUnavailable
	}
	if bytes <= 0 {
		return Usage{}, ErrInvalidSize
	}
	usage, err := s.repo.Reserve(ctx, spaceID, bytes)
	if err != nil {
		return Usage{}, err
	}
	if usage.UsedBytes < 0 || (usage.LimitBytes != nil && usage.UsedBytes > *usage.LimitBytes) {
		return Usage{}, fmt.Errorf("%w: repository returned invalid usage", ErrUnavailable)
	}
	return usage, nil
}

func (s Service) Release(ctx context.Context, spaceID string, bytes int64) (Usage, error) {
	if s.repo == nil || spaceID == "" {
		return Usage{}, ErrUnavailable
	}
	if bytes <= 0 {
		return Usage{}, ErrInvalidSize
	}
	return s.repo.Release(ctx, spaceID, bytes)
}
