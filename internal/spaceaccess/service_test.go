package spaceaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
)

type fakeMemberships map[string]authz.Role

func (f fakeMemberships) RoleForAccount(_ context.Context, accountID, spaceID string) (authz.Role, error) {
	role, ok := f[accountID+":"+spaceID]
	if !ok {
		return "", ErrNotMember
	}
	return role, nil
}

type failingMemberships struct{}

func (failingMemberships) RoleForAccount(context.Context, string, string) (authz.Role, error) {
	return "", errors.New("lookup failed")
}

func TestServiceEnforcesAccountAndSpaceMembership(t *testing.T) {
	t.Parallel()

	svc := New(fakeMemberships{
		"alice:personal-alice": authz.RoleOwner,
		"bob:personal-bob":     authz.RoleOwner,
		"bob:dropbox-alice":    authz.RoleDropOnly,
	})

	if !svc.Allows(context.Background(), "alice", "personal-alice", authz.ActionRead) {
		t.Fatal("owner should read own Space")
	}
	if svc.Allows(context.Background(), "alice", "personal-bob", authz.ActionRead) {
		t.Fatal("account without membership read another personal Space")
	}
	if !svc.Allows(context.Background(), "bob", "dropbox-alice", authz.ActionCreateFile) {
		t.Fatal("drop-only member should upload")
	}
	if svc.Allows(context.Background(), "bob", "dropbox-alice", authz.ActionList) {
		t.Fatal("drop-only member enumerated destination contents")
	}
}

func TestServiceFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		svc  Service
	}{
		{name: "nil resolver", svc: New(nil)},
		{name: "resolver error", svc: New(failingMemberships{})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.svc.Allows(context.Background(), "alice", "space", authz.ActionRead) {
				t.Fatal("authorization unexpectedly allowed access")
			}
		})
	}

	svc := New(fakeMemberships{"alice:space": authz.RoleOwner})
	if svc.Allows(context.Background(), "", "space", authz.ActionRead) {
		t.Fatal("empty account ID allowed")
	}
	if svc.Allows(context.Background(), "alice", "", authz.ActionRead) {
		t.Fatal("empty Space ID allowed")
	}
	if svc.Allows(context.Background(), "alice", "space", authz.Action("unknown")) {
		t.Fatal("unknown action allowed")
	}
}
