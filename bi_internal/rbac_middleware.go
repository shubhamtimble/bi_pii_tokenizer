package bi_internal

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// requireEndpoint is the RBAC authorization gate placed in front of a protected
// route. When the permission layer is disabled it is a pure pass-through, so the
// wrapped handler behaves exactly as before. When enabled it enforces:
//   - X-Role-Code present
//   - role exists and is active
//   - role has an active, allowed endpoint permission for `action`
//
// On success the role code is stashed in the request context for the handler's
// finer-grained PII check.
func (s *Server) requireEndpoint(action EndpointAction, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rbac == nil || !s.rbac.enabled {
			next.ServeHTTP(w, r)
			return
		}

		roleCode := strings.TrimSpace(r.Header.Get("X-Role-Code"))
		if roleCode == "" {
			s.auditEndpointDeny(r, "", action, "denied", "role code is required")
			writeJSONError(w, http.StatusForbidden, "role code is required")
			return
		}

		role, ok, err := s.rbac.GetRole(r.Context(), roleCode)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !ok || !role.IsActive {
			s.auditEndpointDeny(r, roleCode, action, "denied", "not permitted")
			writeJSONError(w, http.StatusForbidden, "not permitted")
			return
		}

		allowed, err := s.rbac.CheckEndpointPermission(r.Context(), roleCode, action)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !allowed {
			s.auditEndpointDeny(r, roleCode, action, "denied", "not permitted")
			writeJSONError(w, http.StatusForbidden, "not permitted")
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyRole{}, roleCode)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// roleFromContext returns the authenticated role code stashed by requireEndpoint,
// or "" if absent.
func roleFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRole{}).(string)
	return v
}

// auditEndpointDeny records an endpoint-level RBAC denial via the existing runtime
// audit logger (best-effort; AuditLogger.Log is a no-op on a nil/disabled logger).
func (s *Server) auditEndpointDeny(r *http.Request, role string, action EndpointAction, decision, msg string) {
	s.audit.Log(AuditEvent{
		Action:   strings.ToLower(string(action)) + "." + decision,
		Decision: decision,
		RoleCode: role,
		Error:    msg,
		IP:       clientIP(r),
	})
}

// auditDeny is the handler-level analogue of auditFail for RBAC denials/expiries:
// it suffixes the action with the decision, sets decision + error, emits the
// audit event, and writes the JSON error response.
func (s *Server) auditDeny(ev AuditEvent, start time.Time, status int, decision, msg string, w http.ResponseWriter) {
	if ev.Action != "" && !strings.HasSuffix(ev.Action, "."+decision) {
		ev.Action += "." + decision
	}
	ev.Decision = decision
	ev.Error = msg
	ev.LatencyMS = time.Since(start).Milliseconds()
	s.audit.Log(ev)
	writeJSONError(w, status, msg)
}
