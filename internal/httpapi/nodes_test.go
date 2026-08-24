package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
	"github.com/GoreeCloud/goreecloud-drive/internal/config"
	"github.com/GoreeCloud/goreecloud-drive/internal/nodes"
)

type httpNodeRepo struct {
	items map[string]nodes.Node
}

func newHTTPNodeRepo() *httpNodeRepo { return &httpNodeRepo{items: map[string]nodes.Node{}} }

func (r *httpNodeRepo) List(_ context.Context, spaceID string, parentID *string) ([]nodes.Node, error) {
	result := []nodes.Node{}
	for _, node := range r.items {
		if node.SpaceID != spaceID || node.TrashedAt != nil || !sameParent(node.ParentID, parentID) {
			continue
		}
		result = append(result, node)
	}
	return result, nil
}

func (r *httpNodeRepo) Get(_ context.Context, spaceID, nodeID string) (nodes.Node, error) {
	node, ok := r.items[nodeID]
	if !ok || node.SpaceID != spaceID || node.TrashedAt != nil {
		return nodes.Node{}, nodes.ErrNotFound
	}
	return node, nil
}

func (r *httpNodeRepo) Create(_ context.Context, node nodes.Node) (nodes.Node, error) {
	r.items[node.ID] = node
	return node, nil
}

func (r *httpNodeRepo) Rename(_ context.Context, spaceID, nodeID, name string) (nodes.Node, error) {
	node, err := r.Get(context.Background(), spaceID, nodeID)
	if err != nil {
		return nodes.Node{}, err
	}
	node.Name = name
	r.items[nodeID] = node
	return node, nil
}

func (r *httpNodeRepo) Trash(_ context.Context, spaceID, nodeID string) (nodes.Node, error) {
	node, err := r.Get(context.Background(), spaceID, nodeID)
	if err != nil {
		return nodes.Node{}, err
	}
	value := "trashed"
	node.TrashedAt = &value
	r.items[nodeID] = node
	return node, nil
}

func sameParent(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func TestNodeEndpointsEnforceMembershipAndCRUDCapabilities(t *testing.T) {
	repo := newHTTPNodeRepo()
	server := NewWithDependencies(
		config.Config{Bind: "127.0.0.1:0", WebDir: t.TempDir()},
		testLogger(),
		Dependencies{
			Principals: fixedPrincipal{accountID: "alice"},
			Memberships: httpMemberships{
				"alice:private": authz.RoleEditor,
			},
			Nodes: repo,
		},
	)

	create := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(create, httptest.NewRequest(
		http.MethodPost,
		"/api/v1/spaces/private/nodes",
		strings.NewReader(`{"kind":"folder","name":"Documents"}`),
	))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var created nodes.Node
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created node: %v", err)
	}
	if created.ID == "" || created.CreatedBy != "alice" {
		t.Fatalf("unexpected created node: %#v", created)
	}

	list := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/v1/spaces/private/nodes", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "Documents") {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}

	rename := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rename, httptest.NewRequest(
		http.MethodPatch,
		"/api/v1/spaces/private/nodes/"+created.ID,
		strings.NewReader(`{"name":"Records"}`),
	))
	if rename.Code != http.StatusOK || !strings.Contains(rename.Body.String(), "Records") {
		t.Fatalf("rename status=%d body=%s", rename.Code, rename.Body.String())
	}

	trash := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(trash, httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/private/nodes/"+created.ID, nil))
	if trash.Code != http.StatusOK || !strings.Contains(trash.Body.String(), "trashed") {
		t.Fatalf("trash status=%d body=%s", trash.Code, trash.Body.String())
	}

	get := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/v1/spaces/private/nodes/"+created.ID, nil))
	if get.Code != http.StatusNotFound {
		t.Fatalf("trashed node get status=%d body=%s", get.Code, get.Body.String())
	}

	otherSpace := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(otherSpace, httptest.NewRequest(http.MethodGet, "/api/v1/spaces/other/nodes", nil))
	if otherSpace.Code != http.StatusForbidden {
		t.Fatalf("cross-space list status=%d body=%s", otherSpace.Code, otherSpace.Body.String())
	}
}

func TestDropOnlyCannotListOrCreateFoldersThroughNodeAPI(t *testing.T) {
	server := NewWithDependencies(
		config.Config{Bind: "127.0.0.1:0", WebDir: t.TempDir()},
		testLogger(),
		Dependencies{
			Principals: fixedPrincipal{accountID: "drop"},
			Memberships: httpMemberships{
				"drop:inbox": authz.RoleDropOnly,
			},
			Nodes: newHTTPNodeRepo(),
		},
	)

	file := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(file, httptest.NewRequest(http.MethodPost, "/api/v1/spaces/inbox/nodes", strings.NewReader(`{"kind":"file","name":"submission.pdf"}`)))
	if file.Code != http.StatusCreated {
		t.Fatalf("drop-only file create status=%d body=%s", file.Code, file.Body.String())
	}

	folder := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(folder, httptest.NewRequest(http.MethodPost, "/api/v1/spaces/inbox/nodes", strings.NewReader(`{"kind":"folder","name":"Visible"}`)))
	if folder.Code != http.StatusForbidden {
		t.Fatalf("drop-only folder create status=%d body=%s", folder.Code, folder.Body.String())
	}

	list := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/v1/spaces/inbox/nodes", nil))
	if list.Code != http.StatusForbidden {
		t.Fatalf("drop-only list status=%d body=%s", list.Code, list.Body.String())
	}
}
