package bi_internal

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Admin permission-management handlers. All are wrapped by requireEndpoint with
// ROLE_MANAGE / PERMISSION_MANAGE in server.go. While PERMISSION_CHECK_ENABLED is
// false the gate is a pass-through, which is the intended bootstrap path: configure
// roles/permissions, then enable the flag.

var canonicalPIITypes = map[string]bool{
	"PAN": true, "AADHAAR": true, "MOBILE": true, "PHONE": true,
	"EMAIL": true, "DL": true, "PASSPORT": true, "VOTERID": true,
}

var canonicalEndpointActions = map[string]bool{
	string(ActionTokenize): true, string(ActionDetokenize): true,
	string(ActionAuditRead): true, string(ActionRoleManage): true,
	string(ActionPermissionManage): true,
}

var canonicalAccess = map[string]bool{
	string(AccessNone): true, string(AccessMasked): true, string(AccessFull): true,
}

// logPermChange writes a configuration-change row to permission_audit_logs
// (best-effort) using the acting role from context and the request IP.
func (s *Server) logPermChange(r *http.Request, action, roleCode, endpointAction, piiType string, oldV, newV []byte, reason, decision string) {
	if s.rbac == nil {
		return
	}
	if err := s.rbac.store.InsertPermissionAuditLog(r.Context(), permAuditEntry{
		Actor:          roleFromContext(r.Context()),
		Action:         action,
		RoleCode:       roleCode,
		EndpointAction: endpointAction,
		PIIType:        piiType,
		OldValue:       oldV,
		NewValue:       newV,
		Reason:         reason,
		Decision:       decision,
		IP:             clientIP(r),
	}); err != nil {
		log.Printf("permission_audit_logs insert failed: %v", err)
	}
}

// reloadRBAC refreshes the in-memory permission cache immediately after a change.
func (s *Server) reloadRBAC(r *http.Request) {
	if s.rbac == nil {
		return
	}
	if err := s.rbac.ReloadCache(r.Context()); err != nil {
		log.Printf("rbac: cache reload after admin update failed: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// POST /admin/roles
func (s *Server) adminCreateRoleHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleCode    string `json:"role_code"`
		RoleName    string `json:"role_name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.RoleCode = strings.TrimSpace(req.RoleCode)
	req.RoleName = strings.TrimSpace(req.RoleName)
	if req.RoleCode == "" || req.RoleName == "" {
		writeJSONError(w, http.StatusBadRequest, "role_code and role_name are required")
		return
	}
	if err := s.rbac.store.CreateRole(r.Context(), req.RoleCode, req.RoleName, req.Description); err != nil {
		log.Printf("admin create role error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "could not create role (it may already exist)")
		return
	}
	newV, _ := json.Marshal(req)
	s.logPermChange(r, "role.created", req.RoleCode, "", "", nil, newV, "", "success")
	s.reloadRBAC(r)
	writeJSON(w, http.StatusCreated, map[string]string{"message": "role created", "role_code": req.RoleCode})
}

// GET /admin/roles
func (s *Server) adminListRolesHandler(w http.ResponseWriter, r *http.Request) {
	roles, err := s.rbac.store.ListRoles(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": roles})
}

// PUT /admin/roles/{role_code}
func (s *Server) adminUpdateRoleHandler(w http.ResponseWriter, r *http.Request) {
	roleCode := strings.TrimSpace(mux.Vars(r)["role_code"])
	var req struct {
		RoleName    string `json:"role_name"`
		Description string `json:"description"`
		IsActive    *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.RoleName = strings.TrimSpace(req.RoleName)
	if req.RoleName == "" {
		writeJSONError(w, http.StatusBadRequest, "role_name is required")
		return
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	n, err := s.rbac.store.UpdateRole(r.Context(), roleCode, req.RoleName, req.Description, isActive)
	if err != nil {
		log.Printf("admin update role error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "could not update role")
		return
	}
	if n == 0 {
		writeJSONError(w, http.StatusNotFound, "role not found")
		return
	}
	newV, _ := json.Marshal(req)
	s.logPermChange(r, "role.updated", roleCode, "", "", nil, newV, "", "success")
	s.reloadRBAC(r)
	writeJSON(w, http.StatusOK, map[string]string{"message": "role updated", "role_code": roleCode})
}

// GET /admin/roles/{role_code}/endpoint-permissions
func (s *Server) adminGetEndpointPermsHandler(w http.ResponseWriter, r *http.Request) {
	roleCode := strings.TrimSpace(mux.Vars(r)["role_code"])
	perms, err := s.rbac.store.GetEndpointPerms(r.Context(), roleCode)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"role_code": roleCode, "data": perms})
}

// PUT /admin/roles/{role_code}/endpoint-permissions
func (s *Server) adminPutEndpointPermsHandler(w http.ResponseWriter, r *http.Request) {
	roleCode := strings.TrimSpace(mux.Vars(r)["role_code"])
	var req struct {
		Reason      string              `json:"reason"`
		Permissions []endpointPermInput `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason) // optional
	if len(req.Permissions) == 0 {
		writeJSONError(w, http.StatusBadRequest, "permissions array is required")
		return
	}
	for i := range req.Permissions {
		req.Permissions[i].EndpointAction = strings.ToUpper(strings.TrimSpace(req.Permissions[i].EndpointAction))
		if !canonicalEndpointActions[req.Permissions[i].EndpointAction] {
			writeJSONError(w, http.StatusBadRequest, "invalid endpoint_action")
			return
		}
	}

	roleID, err := s.rbac.store.roleID(r.Context(), roleCode)
	if err == sql.ErrNoRows {
		writeJSONError(w, http.StatusNotFound, "role not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if err := s.rbac.store.UpsertEndpointPermissions(r.Context(), roleID, req.Permissions); err != nil {
		log.Printf("admin upsert endpoint perms error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "could not update endpoint permissions")
		return
	}
	newV, _ := json.Marshal(req)
	s.logPermChange(r, "endpoint_permission.updated", roleCode, "", "", nil, newV, req.Reason, "success")
	s.reloadRBAC(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "endpoint permissions updated", "count": len(req.Permissions)})
}

// GET /admin/roles/{role_code}/pii-permissions
func (s *Server) adminGetPIIPermsHandler(w http.ResponseWriter, r *http.Request) {
	roleCode := strings.TrimSpace(mux.Vars(r)["role_code"])
	perms, err := s.rbac.store.GetPIIPerms(r.Context(), roleCode)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"role_code": roleCode, "data": perms})
}

// PUT /admin/roles/{role_code}/pii-permissions
func (s *Server) adminPutPIIPermsHandler(w http.ResponseWriter, r *http.Request) {
	roleCode := strings.TrimSpace(mux.Vars(r)["role_code"])
	var req struct {
		Reason      string `json:"reason"`
		Permissions []struct {
			PIIType          string `json:"pii_type"`
			CanTokenize      bool   `json:"can_tokenize"`
			DetokenizeAccess string `json:"detokenize_access"`
			MaskChar         string `json:"mask_char"`
			ValidityPeriod   string `json:"validity_period"`
		} `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason) // optional
	if len(req.Permissions) == 0 {
		writeJSONError(w, http.StatusBadRequest, "permissions array is required")
		return
	}

	now := time.Now().UTC()
	inputs := make([]piiPermInput, 0, len(req.Permissions))
	for _, p := range req.Permissions {
		piiType := strings.ToUpper(strings.TrimSpace(p.PIIType))
		access := strings.ToUpper(strings.TrimSpace(p.DetokenizeAccess))
		period := strings.ToUpper(strings.TrimSpace(p.ValidityPeriod))
		maskChar := strings.ToUpper(strings.TrimSpace(p.MaskChar))
		if maskChar == "" {
			maskChar = "X"
		}
		if !canonicalPIITypes[piiType] {
			writeJSONError(w, http.StatusBadRequest, "invalid pii_type")
			return
		}
		if !canonicalAccess[access] {
			writeJSONError(w, http.StatusBadRequest, "invalid detokenize_access")
			return
		}
		if maskChar != "X" && maskChar != "*" {
			writeJSONError(w, http.StatusBadRequest, "invalid mask_char (X or *)")
			return
		}
		validUntil, verr := validityUntil(period, now)
		if verr != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid validity_period")
			return
		}
		inputs = append(inputs, piiPermInput{
			PIIType:          piiType,
			CanTokenize:      p.CanTokenize,
			DetokenizeAccess: access,
			MaskChar:         maskChar,
			ValidityPeriod:   period,
			ValidFrom:        now,
			ValidUntil:       validUntil,
		})
	}

	roleID, err := s.rbac.store.roleID(r.Context(), roleCode)
	if err == sql.ErrNoRows {
		writeJSONError(w, http.StatusNotFound, "role not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if err := s.rbac.store.UpsertPIIPermissions(r.Context(), roleID, inputs); err != nil {
		log.Printf("admin upsert pii perms error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "could not update pii permissions")
		return
	}
	newV, _ := json.Marshal(req)
	s.logPermChange(r, "pii_permission.updated", roleCode, "", "", nil, newV, req.Reason, "success")
	s.reloadRBAC(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "pii permissions updated", "count": len(inputs)})
}

// POST /admin/permissions/reload-cache
func (s *Server) adminReloadCacheHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.rbac.ReloadCache(r.Context()); err != nil {
		log.Printf("admin reload cache error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "cache reload failed")
		return
	}
	s.logPermChange(r, "cache.reloaded", "", "", "", nil, nil, "", "success")
	writeJSON(w, http.StatusOK, map[string]string{"message": "permission cache reloaded"})
}
