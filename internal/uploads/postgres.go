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
    id, space_id, node_id, parent_node_id, account_id, target_name, expected_size_bytes,
    received_size_bytes, staging_key, state, expires_at
) VALUES ($1, $2, $3, NULLIF($4, '')::uuid, $5, $6, NULL, $7, $8, $9, $10)`,
		session.ID,
		session.SpaceID,
		session.NodeID,
		session.ParentNodeID,
		session.AccountID,
		session.TargetName,
		session.Offset,
		session.ID,
		stateToDatabase(session.State),
		session.ExpiresAt,
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
	var parentNodeID sql.NullString
	var state string
	err := r.DB.QueryRowContext(ctx, `
SELECT id, space_id, node_id, parent_node_id::text, account_id, target_name, received_size_bytes, state, expires_at
FROM upload_sessions
WHERE id = $1`, uploadID).Scan(
		&session.ID,
		&session.SpaceID,
		&session.NodeID,
		&parentNodeID,
		&session.AccountID,
		&session.TargetName,
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
	if parentNodeID.Valid {
		session.ParentNodeID = parentNodeID.String
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
    node_id = $4,
    parent_node_id = NULLIF($5, '')::uuid,
    target_name = $6,
    updated_at = now()
WHERE id = $1`,
		session.ID,
		session.Offset,
		stateToDatabase(session.State),
		session.NodeID,
		session.ParentNodeID,
		session.TargetName,
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
