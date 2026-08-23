// Package spaceaccess resolves durable Space membership before evaluating
// server-side Drive capabilities.
package spaceaccess

import (
	"context"
	"errors"

	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
)

// ErrNotMember means the account has no active membership in the requested Space.
var ErrNotMember = errors.New("space membership not found")

// MembershipResolver resolves the durable role assigned to an account in a Space.
// Persistent implementations must scope the lookup by both account and Space.
type MembershipResolver interface {
	RoleForAccount(context.Context, string, string) (authz.Role, error)
}

// Service combines membership resolution with the fail-closed capability policy.
type Service struct {
	memberships MembershipResolver
}

func New(memberships MembershipResolver) Service {
	return Service{memberships: memberships}
}

// Allows reports whether accountID may perform action in spaceID. A missing
// resolver, missing membership, resolver error, unknown role, or unknown action
// all deny access.
func (s Service) Allows(ctx context.Context, accountID, spaceID string, action authz.Action) bool {
	if s.memberships == nil || accountID == "" || spaceID == "" {
		return false
	}
	role, err := s.memberships.RoleForAccount(ctx, accountID, spaceID)
	if err != nil {
		return false
	}
	return authz.Allows(role, action)
}
