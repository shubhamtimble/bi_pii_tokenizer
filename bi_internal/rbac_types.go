package bi_internal

import "time"

// EndpointAction is the coarse action a route requires. Stored in
// role_endpoint_permissions.endpoint_action.
type EndpointAction string

const (
	ActionTokenize         EndpointAction = "TOKENIZE"
	ActionDetokenize       EndpointAction = "DETOKENIZE"
	ActionAuditRead        EndpointAction = "AUDIT_READ"
	ActionRoleManage       EndpointAction = "ROLE_MANAGE"
	ActionPermissionManage EndpointAction = "PERMISSION_MANAGE"
)

// DetokenizeAccess is the per-(role,pii_type) detokenize level. Stored in
// role_pii_permissions.detokenize_access.
type DetokenizeAccess string

const (
	AccessNone   DetokenizeAccess = "NONE"
	AccessMasked DetokenizeAccess = "MASKED"
	AccessFull   DetokenizeAccess = "FULL"
)

// ctxKeyRole is the context key under which the authenticated role code is
// stashed by requireEndpoint for downstream handlers.
type ctxKeyRole struct{}

// Role is the in-memory snapshot of a roles row.
type Role struct {
	RoleCode string
	IsActive bool
}

// PIIPerm is the in-memory snapshot of a role_pii_permissions row.
type PIIPerm struct {
	CanTokenize      bool
	DetokenizeAccess DetokenizeAccess
	MaskChar         string // "X" (default) or "*" — fill char for MASKED detokenize
	ValidFrom        time.Time
	ValidUntil       *time.Time // nil == FOREVER
	IsActive         bool
}

// active reports whether the permission row itself is enabled.
func (p PIIPerm) active() bool { return p.IsActive }

// expired reports whether the validity window has passed at time now. A nil
// ValidUntil (FOREVER) never expires. A not-yet-started window (now < ValidFrom)
// is treated as not-yet-valid and also reported as expired==true so callers deny.
func (p PIIPerm) expired(now time.Time) bool {
	if now.Before(p.ValidFrom) {
		return true
	}
	if p.ValidUntil == nil {
		return false
	}
	return now.After(*p.ValidUntil)
}
