// Package authz defines GoreeCloud Drive's server-side authorization policy.
package authz

// Role is a durable Space membership role.
type Role string

const (
	RoleOwner       Role = "owner"
	RoleManager     Role = "manager"
	RoleEditor      Role = "editor"
	RoleContributor Role = "contributor"
	RoleCommenter   Role = "commenter"
	RoleViewer      Role = "viewer"
	RoleDropOnly    Role = "drop_only"
)

// Action is a server-side capability evaluated independently from UI visibility.
type Action string

const (
	ActionRead          Action = "read"
	ActionList          Action = "list"
	ActionCreateFile    Action = "create_file"
	ActionCreateFolder  Action = "create_folder"
	ActionUpdate        Action = "update"
	ActionDelete        Action = "delete"
	ActionComment       Action = "comment"
	ActionShare         Action = "share"
	ActionManageMembers Action = "manage_members"
	ActionManageSpace   Action = "manage_space"
)

var roleCapabilities = map[Role]map[Action]struct{}{
	RoleOwner: capabilitySet(
		ActionRead, ActionList, ActionCreateFile, ActionCreateFolder, ActionUpdate,
		ActionDelete, ActionComment, ActionShare, ActionManageMembers, ActionManageSpace,
	),
	RoleManager: capabilitySet(
		ActionRead, ActionList, ActionCreateFile, ActionCreateFolder, ActionUpdate,
		ActionDelete, ActionComment, ActionShare, ActionManageMembers,
	),
	RoleEditor: capabilitySet(
		ActionRead, ActionList, ActionCreateFile, ActionCreateFolder, ActionUpdate,
		ActionDelete, ActionComment, ActionShare,
	),
	RoleContributor: capabilitySet(
		ActionRead, ActionList, ActionCreateFile, ActionCreateFolder, ActionUpdate, ActionComment,
	),
	RoleCommenter: capabilitySet(ActionRead, ActionList, ActionComment),
	RoleViewer:    capabilitySet(ActionRead, ActionList),
	// Drop-only is intentionally unable to enumerate or read destination contents.
	RoleDropOnly: capabilitySet(ActionCreateFile),
}

func capabilitySet(actions ...Action) map[Action]struct{} {
	set := make(map[Action]struct{}, len(actions))
	for _, action := range actions {
		set[action] = struct{}{}
	}
	return set
}

// Allows reports whether a Space role permits an action. Unknown roles and
// actions fail closed.
func Allows(role Role, action Action) bool {
	capabilities, ok := roleCapabilities[role]
	if !ok {
		return false
	}
	_, ok = capabilities[action]
	return ok
}
