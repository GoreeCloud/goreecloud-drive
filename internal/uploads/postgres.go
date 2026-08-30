package uploads

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PostgresRepository persists resumable upload-session metadata in the existing
// upload_sessions table. File bytes remain owned by the staging storage backend.
type PostgresRepository struct {
	DB *sql.DB
}

func (r PostgresRepository) Create(ctx context.Context, session Session) error {
	if r.DB == nil {
		return fmt.Errorf("upload repository unavailable")
	}
	_, err := r.DB.ExecContext(ctx, `
INSERT INTO upload_sessions (
    id, space_id, account_id, node_id, offset_bytes, state, expires_at, staging_key
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		session.ID,
		session.SpaceID,
		session.AccountID,
		session.NodeID,
		session.Offset,
		string(session.State),
		session.ExpiresAt,
		session.ID,
	)
	if err != nil {
		return fmt.Errorf("create upload session: %w", err)
	}
	return nil
}

func (r PostgresRepository) Get(ctx context.Context, uploadID string) (Session, error) {
	if r.DB == nil {
		return Session{}, fmt.Errorf("upload repository unavailable")
	}
	var session Session
	var state string
	err := r.DB.QueryRowContext(ctx, `
SELECT id, space_id, account_id, node_id, received_size_bytes, state, expires_at
FROM upload_sessions
WHERE id = $1`, uploadID).Scan(
		&session.ID,
		&session.SpaceID,
		&session.AccountID,
		&session.NodeID,
		&session.Offset,
		&state,
		&session.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("get upload session: %w", err)
	}
	session.State = stateFromDatabase(state)
	return session, nil
}

func (r PostgresRepository) Update(ctx context.Context, session Session) error {
	if r.DB == nil {
		return fmt.Errorf("upload repository unavailable")
	}
	result, err := r.DB.ExecContext(ctx, `
UPDATE upload_sessions
SET received_size_bytes = $2,
    state = $3,
    updated_at = now(),
    finalized_node_id = CASE WHEN $3 = 'complete' THEN $4 ELSE finalized_node_id END
WHERE id = $1`,
		session.ID,
		session.Offset,
		stateToDatabase(session.State),
		session.NodeID,
	)
	if err != nil {
		return fmt.Errorf("update upload session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect upload-session update: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func stateToDatabase(state State) string {
	if state == StateCompleted {
		return "complete"
	}
	return "open"
}

func stateFromDatabase(state string) State {
	if state == "complete" {
		return StateCompleted
	}
	return StateActive
}
