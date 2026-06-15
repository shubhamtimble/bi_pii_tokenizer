package bi_internal

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// adminOverviewHandler (GET /admin/overview) returns config + aggregate stats in
// one call, powering both the Dashboard cards and the Settings status panel.
func (s *Server) adminOverviewHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := s.rbac.store.OverviewStats(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query failed")
		return
	}

	type configResp struct {
		PermissionCheckEnabled bool    `json:"permission_check_enabled"`
		CacheTTLSeconds        int     `json:"cache_ttl_seconds"`
		LastReloadAt           *string `json:"last_reload_at"`
	}
	cfg := configResp{
		PermissionCheckEnabled: s.rbac.Enabled(),
		CacheTTLSeconds:        s.rbac.TTLSeconds(),
	}
	if t, ok := s.rbac.LastReload(); ok {
		ts := t.UTC().Format(time.RFC3339)
		cfg.LastReloadAt = &ts
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"config": cfg,
		"stats":  stats,
	})
}

// permAuditRecord is one row of the permission-change audit log.
type permAuditRecord struct {
	EventID        string           `json:"event_id"`
	OccurredAt     string           `json:"occurred_at"`
	Actor          *string          `json:"actor"`
	Action         string           `json:"action"`
	RoleCode       *string          `json:"role_code"`
	EndpointAction *string          `json:"endpoint_action"`
	PIIType        *string          `json:"pii_type"`
	OldValue       *json.RawMessage `json:"old_value"`
	NewValue       *json.RawMessage `json:"new_value"`
	Reason         *string          `json:"reason"`
	Decision       string           `json:"decision"`
	IP             *string          `json:"ip"`
}

// adminPermissionAuditHandler (GET /admin/permission-audit) serves the
// configuration-change log with filters and opaque-cursor pagination (newest
// first by id). Mirrors auditEventsHandler.
func (s *Server) adminPermissionAuditHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := 100
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			switch {
			case n < 1:
				limit = 1
			case n > 500:
				limit = 500
			default:
				limit = n
			}
		}
	}

	conds := []string{}
	args := []interface{}{}
	addArg := func(v interface{}) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			conds = append(conds, "occurred_at >= "+addArg(t))
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			conds = append(conds, "occurred_at <= "+addArg(t))
		}
	}
	if v := q.Get("actor"); v != "" {
		conds = append(conds, "actor = "+addArg(v))
	}
	if v := q.Get("role_code"); v != "" {
		conds = append(conds, "role_code = "+addArg(v))
	}
	if v := q.Get("action"); v != "" {
		conds = append(conds, "action = "+addArg(v))
	}
	if v := q.Get("pii_type"); v != "" {
		conds = append(conds, "pii_type = "+addArg(strings.ToUpper(v)))
	}
	if v := q.Get("decision"); v != "" {
		conds = append(conds, "decision = "+addArg(v))
	}
	if v := q.Get("cursor"); v != "" {
		if data, err := base64.URLEncoding.DecodeString(v); err == nil {
			var c struct {
				ID int64 `json:"id"`
			}
			if json.Unmarshal(data, &c) == nil && c.ID > 0 {
				conds = append(conds, "id < "+addArg(c.ID))
			}
		}
	}

	sqlStr := `SELECT id, event_id, occurred_at, actor, action, role_code, endpoint_action,
	                  pii_type, old_value, new_value, reason, decision, ip
	           FROM permission_audit_logs`
	if len(conds) > 0 {
		sqlStr += " WHERE " + strings.Join(conds, " AND ")
	}
	sqlStr += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args)+1)
	args = append(args, limit+1)

	rows, err := s.rbac.store.db.QueryContext(r.Context(), sqlStr, args...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	out := make([]permAuditRecord, 0, limit)
	lastID := int64(0)
	hasMore := false
	for rows.Next() {
		var (
			id             int64
			eventID        string
			occurredAt     time.Time
			actor          sql.NullString
			action         string
			roleCode       sql.NullString
			endpointAction sql.NullString
			piiType        sql.NullString
			oldValue       []byte
			newValue       []byte
			reason         sql.NullString
			decision       string
			ip             sql.NullString
		)
		if err := rows.Scan(&id, &eventID, &occurredAt, &actor, &action, &roleCode, &endpointAction,
			&piiType, &oldValue, &newValue, &reason, &decision, &ip); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		if len(out) >= limit {
			hasMore = true
			break
		}
		rec := permAuditRecord{
			EventID:        eventID,
			OccurredAt:     occurredAt.UTC().Format(time.RFC3339Nano),
			Actor:          nullStrPtr(actor),
			Action:         action,
			RoleCode:       nullStrPtr(roleCode),
			EndpointAction: nullStrPtr(endpointAction),
			PIIType:        nullStrPtr(piiType),
			Reason:         nullStrPtr(reason),
			Decision:       decision,
			IP:             nullStrPtr(ip),
		}
		if len(oldValue) > 0 {
			rm := json.RawMessage(oldValue)
			rec.OldValue = &rm
		}
		if len(newValue) > 0 {
			rm := json.RawMessage(newValue)
			rec.NewValue = &rm
		}
		out = append(out, rec)
		lastID = id
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "iter failed")
		return
	}

	resp := map[string]interface{}{"data": out}
	meta := map[string]interface{}{"limit": limit}
	if hasMore && lastID > 0 {
		cursor, _ := json.Marshal(struct {
			ID int64 `json:"id"`
		}{lastID})
		meta["next_cursor"] = base64.URLEncoding.EncodeToString(cursor)
	}
	resp["meta"] = meta
	writeJSON(w, http.StatusOK, resp)
}
