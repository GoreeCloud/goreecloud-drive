package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type PostgresRepository struct {
	DB *sql.DB
}

func (r PostgresRepository) Get(ctx context.Context, spaceID string) (Usage, error) {
	if r.DB == nil {
		return Usage{}, ErrUnavailable
	}
	var usage Usage
	var limit sql.NullInt64
	err := r.DB.QueryRowContext(ctx, `SELECT space_id::text, limit_bytes, used_bytes FROM quotas WHERE space_id = $1`, spaceID).Scan(&usage.SpaceID, &limit, &usage.UsedBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return Usage{}, ErrUnavailable
	}
	if err != nil {
		return Usage{}, fmt.Errorf("read quota: %w", err)
	}
	if limit.Valid {
		v := limit.Int64
		usage.LimitBytes = &v
	}
	return usage, nil
}

func (r PostgresRepository) Reserve(ctx context.Context, spaceID string, bytes int64) (Usage, error) {
	if r.DB == nil {
		return Usage{}, ErrUnavailable
	}
	var usage Usage
	var limit sql.NullInt64
	err := r.DB.QueryRowContext(ctx, `
UPDATE quotas
SET used_bytes = used_bytes + $2, updated_at = now()
WHERE space_id = $1
  AND $2 > 0
  AND (limit_bytes IS NULL OR used_bytes + $2 <= limit_bytes)
RETURNING space_id::text, limit_bytes, used_bytes`, spaceID, bytes).Scan(&usage.SpaceID, &limit, &usage.UsedBytes)
	if errors.Is(err, sql.ErrNoRows) {
		if _, getErr := r.Get(ctx, spaceID); getErr != nil {
			return Usage{}, getErr
		}
		return Usage{}, ErrExceeded
	}
	if err != nil {
		return Usage{}, fmt.Errorf("reserve quota: %w", err)
	}
	if limit.Valid {
		v := limit.Int64
		usage.LimitBytes = &v
	}
	return usage, nil
}

func (r PostgresRepository) Release(ctx context.Context, spaceID string, bytes int64) (Usage, error) {
	if r.DB == nil {
		return Usage{}, ErrUnavailable
	}
	var usage Usage
	var limit sql.NullInt64
	err := r.DB.QueryRowContext(ctx, `
UPDATE quotas
SET used_bytes = GREATEST(used_bytes - $2, 0), updated_at = now()
WHERE space_id = $1 AND $2 > 0
RETURNING space_id::text, limit_bytes, used_bytes`, spaceID, bytes).Scan(&usage.SpaceID, &limit, &usage.UsedBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return Usage{}, ErrUnavailable
	}
	if err != nil {
		return Usage{}, fmt.Errorf("release quota: %w", err)
	}
	if limit.Valid {
		v := limit.Int64
		usage.LimitBytes = &v
	}
	return usage, nil
}
