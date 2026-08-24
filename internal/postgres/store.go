// Package postgres provides PostgreSQL persistence adapters for Drive services.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
	"github.com/GoreeCloud/goreecloud-drive/internal/nodes"
	"github.com/GoreeCloud/goreecloud-drive/internal/spaceaccess"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) RoleForAccount(ctx context.Context, accountID, spaceID string) (authz.Role, error) {
	if s == nil || s.db == nil {
		return "", spaceaccess.ErrNotMember
	}
	var role string
	err := s.db.QueryRowContext(ctx, `
		SELECT role
		FROM space_memberships
		WHERE space_id = $1::uuid AND account_id = $2::uuid
	`, spaceID, accountID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", spaceaccess.ErrNotMember
	}
	if err != nil {
		return "", err
	}
	return authz.Role(role), nil
}

func (s *Store) List(ctx context.Context, spaceID string, parentID *string) ([]nodes.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, space_id::text, parent_id::text, kind, name, created_by::text,
		       created_at, modified_at, trashed_at
		FROM nodes
		WHERE space_id = $1::uuid
		  AND (($2::uuid IS NULL AND parent_id IS NULL) OR parent_id = $2::uuid)
		  AND trashed_at IS NULL
		ORDER BY kind DESC, lower(name), id
	`, spaceID, nullableString(parentID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []nodes.Node
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, node)
	}
	return result, rows.Err()
}

func (s *Store) Get(ctx context.Context, spaceID, nodeID string) (nodes.Node, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, space_id::text, parent_id::text, kind, name, created_by::text,
		       created_at, modified_at, trashed_at
		FROM nodes
		WHERE id = $1::uuid AND space_id = $2::uuid AND trashed_at IS NULL
	`, nodeID, spaceID)
	node, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nodes.Node{}, nodes.ErrNotFound
	}
	return node, err
}

func (s *Store) Create(ctx context.Context, node nodes.Node) (nodes.Node, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO nodes (id, space_id, parent_id, kind, name, created_by)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6::uuid)
		RETURNING id::text, space_id::text, parent_id::text, kind, name, created_by::text,
		          created_at, modified_at, trashed_at
	`, node.ID, node.SpaceID, nullableString(node.ParentID), node.Kind, node.Name, node.CreatedBy)
	return scanNode(row)
}

func (s *Store) Rename(ctx context.Context, spaceID, nodeID, name string) (nodes.Node, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE nodes
		SET name = $3, modified_at = now()
		WHERE id = $1::uuid AND space_id = $2::uuid AND trashed_at IS NULL
		RETURNING id::text, space_id::text, parent_id::text, kind, name, created_by::text,
		          created_at, modified_at, trashed_at
	`, nodeID, spaceID, name)
	node, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nodes.Node{}, nodes.ErrNotFound
	}
	return node, err
}

func (s *Store) Trash(ctx context.Context, spaceID, nodeID string) (nodes.Node, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE nodes
		SET trashed_at = now(), modified_at = now()
		WHERE id = $1::uuid AND space_id = $2::uuid AND trashed_at IS NULL
		RETURNING id::text, space_id::text, parent_id::text, kind, name, created_by::text,
		          created_at, modified_at, trashed_at
	`, nodeID, spaceID)
	node, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nodes.Node{}, nodes.ErrNotFound
	}
	return node, err
}

type scanner interface {
	Scan(...any) error
}

func scanNode(row scanner) (nodes.Node, error) {
	var (
		node       nodes.Node
		parentID   sql.NullString
		kind       string
		createdAt  time.Time
		modifiedAt time.Time
		trashedAt  sql.NullTime
	)
	if err := row.Scan(
		&node.ID, &node.SpaceID, &parentID, &kind, &node.Name, &node.CreatedBy,
		&createdAt, &modifiedAt, &trashedAt,
	); err != nil {
		return nodes.Node{}, err
	}
	node.Kind = nodes.Kind(kind)
	if parentID.Valid {
		node.ParentID = &parentID.String
	}
	node.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
	node.ModifiedAt = modifiedAt.UTC().Format(time.RFC3339Nano)
	if trashedAt.Valid {
		value := trashedAt.Time.UTC().Format(time.RFC3339Nano)
		node.TrashedAt = &value
	}
	return node, nil
}

func nullableString(value *string) any {
	if value == nil || *value == "" {
		return nil
	}
	return *value
}
