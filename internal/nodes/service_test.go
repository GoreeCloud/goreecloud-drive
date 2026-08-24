package nodes

import (
	"context"
	"errors"
	"testing"

	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
)

type testAuthorizer map[authz.Action]bool

func (a testAuthorizer) Allows(_ context.Context, _, _ string, action authz.Action) bool {
	return a[action]
}

type memoryRepo struct {
	created []Node
}

func (r *memoryRepo) List(_ context.Context, spaceID string, _ *string) ([]Node, error) {
	var result []Node
	for _, node := range r.created {
		if node.SpaceID == spaceID && node.TrashedAt == nil {
			result = append(result, node)
		}
	}
	return result, nil
}

func (r *memoryRepo) Get(_ context.Context, spaceID, nodeID string) (Node, error) {
	for _, node := range r.created {
		if node.SpaceID == spaceID && node.ID == nodeID && node.TrashedAt == nil {
			return node, nil
		}
	}
	return Node{}, ErrNotFound
}

func (r *memoryRepo) Create(_ context.Context, node Node) (Node, error) {
	r.created = append(r.created, node)
	return node, nil
}

func (r *memoryRepo) Rename(_ context.Context, spaceID, nodeID, name string) (Node, error) {
	for i := range r.created {
		if r.created[i].SpaceID == spaceID && r.created[i].ID == nodeID {
			r.created[i].Name = name
			return r.created[i], nil
		}
	}
	return Node{}, ErrNotFound
}

func (r *memoryRepo) Trash(_ context.Context, spaceID, nodeID string) (Node, error) {
	for i := range r.created {
		if r.created[i].SpaceID == spaceID && r.created[i].ID == nodeID {
			value := "trashed"
			r.created[i].TrashedAt = &value
			return r.created[i], nil
		}
	}
	return Node{}, ErrNotFound
}

func TestCreateUsesCapabilityForKind(t *testing.T) {
	repo := &memoryRepo{}
	service := New(repo, testAuthorizer{authz.ActionCreateFile: true})

	file, err := service.Create(context.Background(), "account", "space", nil, KindFile, "report.txt")
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	if file.ID == "" || file.CreatedBy != "account" || file.SpaceID != "space" {
		t.Fatalf("unexpected file: %#v", file)
	}

	_, err = service.Create(context.Background(), "account", "space", nil, KindFolder, "Folder")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("folder create should be forbidden, got %v", err)
	}
}

func TestDropOnlyStyleAuthorizerCannotEnumerate(t *testing.T) {
	repo := &memoryRepo{}
	service := New(repo, testAuthorizer{authz.ActionCreateFile: true})

	if _, err := service.Create(context.Background(), "drop", "space", nil, KindFile, "upload.bin"); err != nil {
		t.Fatalf("drop-only create file: %v", err)
	}
	if _, err := service.List(context.Background(), "drop", "space", nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("drop-only list should be forbidden, got %v", err)
	}
}

func TestInvalidNamesFailBeforeRepositoryWrite(t *testing.T) {
	repo := &memoryRepo{}
	service := New(repo, testAuthorizer{authz.ActionCreateFile: true, authz.ActionUpdate: true})

	for _, name := range []string{"", "..", "a/b", "a\\b", "bad\nname"} {
		if _, err := service.Create(context.Background(), "account", "space", nil, KindFile, name); !errors.Is(err, ErrInvalid) {
			t.Fatalf("name %q should be invalid, got %v", name, err)
		}
	}
	if len(repo.created) != 0 {
		t.Fatalf("invalid input reached repository: %#v", repo.created)
	}
}

func TestNilRepositoryFailsClosed(t *testing.T) {
	service := New(nil, testAuthorizer{authz.ActionRead: true})
	_, err := service.Get(context.Background(), "account", "space", "node")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}
