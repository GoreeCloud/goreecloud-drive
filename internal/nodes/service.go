// Package nodes owns the authorization-aware file and folder metadata service.
package nodes

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
)

var (
	ErrForbidden   = errors.New("node access denied")
	ErrInvalid     = errors.New("invalid node input")
	ErrNotFound    = errors.New("node not found")
	ErrUnavailable = errors.New("node repository unavailable")
)

type Kind string

const (
	KindFile   Kind = "file"
	KindFolder Kind = "folder"
)

type Node struct {
	ID        string  `json:"id"`
	SpaceID   string  `json:"space_id"`
	ParentID  *string `json:"parent_id,omitempty"`
	Kind      Kind    `json:"kind"`
	Name      string  `json:"name"`
	CreatedBy string  `json:"created_by"`
	CreatedAt string  `json:"created_at,omitempty"`
	ModifiedAt string `json:"modified_at,omitempty"`
	TrashedAt *string `json:"trashed_at,omitempty"`
}

type Repository interface {
	List(context.Context, string, *string) ([]Node, error)
	Get(context.Context, string, string) (Node, error)
	Create(context.Context, Node) (Node, error)
	Rename(context.Context, string, string, string) (Node, error)
	Trash(context.Context, string, string) (Node, error)
}

type Authorizer interface {
	Allows(context.Context, string, string, authz.Action) bool
}

type Service struct {
	repo Repository
	auth Authorizer
}

func New(repo Repository, auth Authorizer) Service {
	return Service{repo: repo, auth: auth}
}

func (s Service) List(ctx context.Context, accountID, spaceID string, parentID *string) ([]Node, error) {
	if !s.allowed(ctx, accountID, spaceID, authz.ActionList) {
		return nil, ErrForbidden
	}
	if s.repo == nil {
		return nil, ErrUnavailable
	}
	return s.repo.List(ctx, spaceID, parentID)
}

func (s Service) Get(ctx context.Context, accountID, spaceID, nodeID string) (Node, error) {
	if !s.allowed(ctx, accountID, spaceID, authz.ActionRead) {
		return Node{}, ErrForbidden
	}
	if s.repo == nil {
		return Node{}, ErrUnavailable
	}
	return s.repo.Get(ctx, spaceID, nodeID)
}

func (s Service) Create(ctx context.Context, accountID, spaceID string, parentID *string, kind Kind, name string) (Node, error) {
	action := authz.ActionCreateFile
	if kind == KindFolder {
		action = authz.ActionCreateFolder
	} else if kind != KindFile {
		return Node{}, ErrInvalid
	}
	if !validName(name) {
		return Node{}, ErrInvalid
	}
	if !s.allowed(ctx, accountID, spaceID, action) {
		return Node{}, ErrForbidden
	}
	if s.repo == nil {
		return Node{}, ErrUnavailable
	}
	id, err := newUUID()
	if err != nil {
		return Node{}, fmt.Errorf("generate node id: %w", err)
	}
	return s.repo.Create(ctx, Node{
		ID:        id,
		SpaceID:   spaceID,
		ParentID:  parentID,
		Kind:      kind,
		Name:      strings.TrimSpace(name),
		CreatedBy: accountID,
	})
}

func (s Service) Rename(ctx context.Context, accountID, spaceID, nodeID, name string) (Node, error) {
	if !validName(name) {
		return Node{}, ErrInvalid
	}
	if !s.allowed(ctx, accountID, spaceID, authz.ActionUpdate) {
		return Node{}, ErrForbidden
	}
	if s.repo == nil {
		return Node{}, ErrUnavailable
	}
	return s.repo.Rename(ctx, spaceID, nodeID, strings.TrimSpace(name))
}

func (s Service) Trash(ctx context.Context, accountID, spaceID, nodeID string) (Node, error) {
	if !s.allowed(ctx, accountID, spaceID, authz.ActionDelete) {
		return Node{}, ErrForbidden
	}
	if s.repo == nil {
		return Node{}, ErrUnavailable
	}
	return s.repo.Trash(ctx, spaceID, nodeID)
}

func (s Service) allowed(ctx context.Context, accountID, spaceID string, action authz.Action) bool {
	return s.auth != nil && accountID != "" && spaceID != "" && s.auth.Allows(ctx, accountID, spaceID, action)
}

func validName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 255 || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
