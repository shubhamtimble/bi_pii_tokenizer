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

// AuditEventRecord is a single audit row as returned by GET /audit/events.
// JSON shape matches the spec: event_id is the row id formatted as a string.
type AuditEventRecord struct {
	EventID    string  `json:"event_id"`
	OccurredAt string  `json:"occurred_at"`
	Action     string  `json:"action"`
	Actor      *string `json:"actor"`
	RoleCode   *string `json:"role_code"`
	PIIType    *string `json:"pii_type"`
	FPT        *string `json:"fpt"`
	ValueHash  *string `json:"value_hash"`
	Reason     *string `json:"reason"`
	Decision   string  `json:"decision"`
	IP         *string `json:"ip"`
	LatencyMS  int64   `json:"latency_ms"`
}

type auditEventsResponse struct {
	Data []AuditEventRecord `json:"data"`
	Meta struct {
		NextCursor string `json:"next_cursor"`
		Limit      int    `json:"limit"`
	} `json:"meta"`
}

// auditEventsHandler serves GET /api/fpt-tokenization/audit/events with the
// filters listed in the spec. Pagination is opaque-cursor based on the row id
// (newest first); next_cursor is base64({"id":<last_returned_id>}).
func (s *Server) auditEventsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// limit (1..500, default 100)
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

	// dynamic WHERE
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
	if v := q.Get("action"); v != "" {
		conds = append(conds, "action = "+addArg(v))
	}
	if v := q.Get("reason"); v != "" {
		conds = append(conds, "reason = "+addArg(v))
	}
	if v := q.Get("actor"); v != "" {
		conds = append(conds, "actor = "+addArg(v))
	}
	if v := q.Get("role_code"); v != "" {
		conds = append(conds, "role_code = "+addArg(v))
	}
	if v := q.Get("pii_type"); v != "" {
		conds = append(conds, "pii_type = "+addArg(strings.ToUpper(v)))
	}
	if v := q.Get("decision"); v != "" {
		conds = append(conds, "decision = "+addArg(v))
	}

	// cursor → id < cursor.id
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

	// We SELECT both `id` (internal monotonic cursor) and `event_id` (public
	// UUID returned to clients). Pagination still walks newest-first by `id`.
	sqlStr := `SELECT id, event_id, occurred_at, action, actor, pii_type, fpt,
                       value_hash, reason, decision, ip, latency_ms, role_code
                FROM pii_audit_logs`
	if len(conds) > 0 {
		sqlStr += " WHERE " + strings.Join(conds, " AND ")
	}
	sqlStr += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args)+1)
	args = append(args, limit+1) // fetch one extra to know if there's a next page

	rows, err := s.store.DB().QueryContext(r.Context(), sqlStr, args...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	out := make([]AuditEventRecord, 0, limit)
	lastReturnedID := int64(0)
	hasMore := false
	for rows.Next() {
		var (
			id         int64
			eventID    string
			occurredAt time.Time
			action     string
			actor      sql.NullString
			piiType    sql.NullString
			fpt        sql.NullString
			valueHash  sql.NullString
			reason     sql.NullString
			decision   string
			ip         sql.NullString
			latencyMS  sql.NullInt64
			roleCode   sql.NullString
		)
		if err := rows.Scan(&id, &eventID, &occurredAt, &action, &actor, &piiType, &fpt,
			&valueHash, &reason, &decision, &ip, &latencyMS, &roleCode); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		if len(out) >= limit {
			// This is the +1 lookahead row → mark "has more" and stop adding.
			hasMore = true
			break
		}
		out = append(out, AuditEventRecord{
			EventID:    eventID,
			OccurredAt: occurredAt.UTC().Format(time.RFC3339Nano),
			Action:     action,
			Actor:      nullStrPtr(actor),
			RoleCode:   nullStrPtr(roleCode),
			PIIType:    nullStrPtr(piiType),
			FPT:        nullStrPtr(fpt),
			ValueHash:  nullStrPtr(valueHash),
			Reason:     nullStrPtr(reason),
			Decision:   decision,
			IP:         nullStrPtr(ip),
			LatencyMS:  latencyMS.Int64,
		})
		lastReturnedID = id
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "iter failed")
		return
	}

	resp := auditEventsResponse{Data: out}
	resp.Meta.Limit = limit
	if hasMore && lastReturnedID > 0 {
		cursor, _ := json.Marshal(struct {
			ID int64 `json:"id"`
		}{lastReturnedID})
		resp.Meta.NextCursor = base64.URLEncoding.EncodeToString(cursor)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func nullStrPtr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}
