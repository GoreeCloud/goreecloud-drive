package authz

import "testing"

func TestRoleCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		role   Role
		action Action
		want   bool
	}{
		{name: "owner manages space", role: RoleOwner, action: ActionManageSpace, want: true},
		{name: "manager cannot manage space", role: RoleManager, action: ActionManageSpace, want: false},
		{name: "editor shares", role: RoleEditor, action: ActionShare, want: true},
		{name: "contributor cannot delete", role: RoleContributor, action: ActionDelete, want: false},
		{name: "commenter comments", role: RoleCommenter, action: ActionComment, want: true},
		{name: "viewer reads", role: RoleViewer, action: ActionRead, want: true},
		{name: "viewer cannot write", role: RoleViewer, action: ActionCreateFile, want: false},
		{name: "drop only uploads", role: RoleDropOnly, action: ActionCreateFile, want: true},
		{name: "drop only cannot list", role: RoleDropOnly, action: ActionList, want: false},
		{name: "drop only cannot read", role: RoleDropOnly, action: ActionRead, want: false},
		{name: "unknown role fails closed", role: Role("administrator"), action: ActionRead, want: false},
		{name: "unknown action fails closed", role: RoleOwner, action: Action("impersonate"), want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Allows(tt.role, tt.action); got != tt.want {
				t.Fatalf("Allows(%q, %q) = %v, want %v", tt.role, tt.action, got, tt.want)
			}
		})
	}
}

func TestEveryRoleFailsClosedForUnknownAction(t *testing.T) {
	t.Parallel()

	roles := []Role{
		RoleOwner,
		RoleManager,
		RoleEditor,
		RoleContributor,
		RoleCommenter,
		RoleViewer,
		RoleDropOnly,
	}
	for _, role := range roles {
		if Allows(role, Action("unknown")) {
			t.Fatalf("role %q allowed an unknown action", role)
		}
	}
}
