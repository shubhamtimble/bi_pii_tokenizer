package bi_internal

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// rbacStore wraps the DB handle used by the RBAC layer. It reuses the same
// *sql.DB as the token vault (models.Store.DB()).
type rbacStore struct {
	db *sql.DB
}

// rbacSnapshot is the full set of RBAC rules loaded into memory.
type rbacSnapshot struct {
	roles    map[string]Role    // role_code -> Role
	endpoint map[string]bool    // "role|ACTION" -> allowed
	pii      map[string]PIIPerm // "role|PIITYPE" -> perm
}

func endpointKey(role string, action EndpointAction) string { return role + "|" + string(action) }
func piiKey(role, piiType string) string                    { return role + "|" + piiType }

// LoadSnapshot streams all roles + permissions into in-memory maps.
func (s *rbacStore) LoadSnapshot(ctx context.Context) (*rbacSnapshot, error) {
	snap := &rbacSnapshot{
		roles:    map[string]Role{},
		endpoint: map[string]bool{},
		pii:      map[string]PIIPerm{},
	}

	roleRows, err := s.db.QueryContext(ctx, `SELECT role_code, is_active FROM roles`)
	if err != nil {
		return nil, fmt.Errorf("load roles: %w", err)
	}
	defer roleRows.Close()
	for roleRows.Next() {
		var r Role
		if err := roleRows.Scan(&r.RoleCode, &r.IsActive); err != nil {
			return nil, err
		}
		snap.roles[r.RoleCode] = r
	}
	if err := roleRows.Err(); err != nil {
		return nil, err
	}

	epRows, err := s.db.QueryContext(ctx, `
		SELECT r.role_code, rep.endpoint_action, rep.allowed
		FROM role_endpoint_permissions rep
		JOIN roles r ON r.id = rep.role_id
		WHERE rep.is_active = TRUE`)
	if err != nil {
		return nil, fmt.Errorf("load endpoint perms: %w", err)
	}
	defer epRows.Close()
	for epRows.Next() {
		var role, action string
		var allowed bool
		if err := epRows.Scan(&role, &action, &allowed); err != nil {
			return nil, err
		}
		snap.endpoint[role+"|"+action] = allowed
	}
	if err := epRows.Err(); err != nil {
		return nil, err
	}

	piiRows, err := s.db.QueryContext(ctx, `
		SELECT r.role_code, p.pii_type, p.can_tokenize, p.detokenize_access,
		       p.mask_char, p.valid_from, p.valid_until, p.is_active
		FROM role_pii_permissions p
		JOIN roles r ON r.id = p.role_id`)
	if err != nil {
		return nil, fmt.Errorf("load pii perms: %w", err)
	}
	defer piiRows.Close()
	for piiRows.Next() {
		var role, piiType, access, maskChar string
		var canTok, isActive bool
		var validFrom time.Time
		var validUntil sql.NullTime
		if err := piiRows.Scan(&role, &piiType, &canTok, &access, &maskChar, &validFrom, &validUntil, &isActive); err != nil {
			return nil, err
		}
		p := PIIPerm{
			CanTokenize:      canTok,
			DetokenizeAccess: DetokenizeAccess(access),
			MaskChar:         maskChar,
			ValidFrom:        validFrom,
			IsActive:         isActive,
		}
		if validUntil.Valid {
			t := validUntil.Time
			p.ValidUntil = &t
		}
		snap.pii[role+"|"+piiType] = p
	}
	if err := piiRows.Err(); err != nil {
		return nil, err
	}

	return snap, nil
}

// GetRoleFromDB is the single-row fallback used when the cache is unavailable.
func (s *rbacStore) GetRoleFromDB(ctx context.Context, roleCode string) (Role, bool, error) {
	var r Role
	err := s.db.QueryRowContext(ctx, `SELECT role_code, is_active FROM roles WHERE role_code = $1`, roleCode).
		Scan(&r.RoleCode, &r.IsActive)
	if err == sql.ErrNoRows {
		return Role{}, false, nil
	}
	if err != nil {
		return Role{}, false, err
	}
	return r, true, nil
}

// CheckEndpointPermissionFromDB returns whether an active role has an active,
// allowed endpoint permission. Missing row => false (deny by default).
func (s *rbacStore) CheckEndpointPermissionFromDB(ctx context.Context, roleCode string, action EndpointAction) (bool, error) {
	var allowed bool
	err := s.db.QueryRowContext(ctx, `
		SELECT rep.allowed
		FROM role_endpoint_permissions rep
		JOIN roles r ON r.id = rep.role_id
		WHERE r.role_code = $1 AND r.is_active = TRUE
		  AND rep.endpoint_action = $2 AND rep.is_active = TRUE`,
		roleCode, string(action)).Scan(&allowed)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return allowed, nil
}

// GetPIIPermFromDB is the single-row fallback for a (role, pii_type) perm.
func (s *rbacStore) GetPIIPermFromDB(ctx context.Context, roleCode, piiType string) (PIIPerm, bool, error) {
	var access, maskChar string
	var canTok, isActive bool
	var validFrom time.Time
	var validUntil sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT p.can_tokenize, p.detokenize_access, p.mask_char, p.valid_from, p.valid_until, p.is_active
		FROM role_pii_permissions p
		JOIN roles r ON r.id = p.role_id
		WHERE r.role_code = $1 AND r.is_active = TRUE AND p.pii_type = $2`,
		roleCode, piiType).Scan(&canTok, &access, &maskChar, &validFrom, &validUntil, &isActive)
	if err == sql.ErrNoRows {
		return PIIPerm{}, false, nil
	}
	if err != nil {
		return PIIPerm{}, false, err
	}
	p := PIIPerm{
		CanTokenize:      canTok,
		DetokenizeAccess: DetokenizeAccess(access),
		MaskChar:         maskChar,
		ValidFrom:        validFrom,
		IsActive:         isActive,
	}
	if validUntil.Valid {
		t := validUntil.Time
		p.ValidUntil = &t
	}
	return p, true, nil
}

// overviewStats are the aggregate counts shown on the dashboard.
type overviewStats struct {
	RolesTotal  int `json:"roles_total"`
	RolesActive int `json:"roles_active"`
	PIIFull     int `json:"pii_full"`
	PIIMasked   int `json:"pii_masked"`
	PIIExpired  int `json:"pii_expired"`
}

// OverviewStats returns cheap aggregate counts for the dashboard in one query.
func (s *rbacStore) OverviewStats(ctx context.Context) (overviewStats, error) {
	var st overviewStats
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT count(*) FROM roles),
			(SELECT count(*) FROM roles WHERE is_active),
			(SELECT count(*) FROM role_pii_permissions WHERE is_active AND detokenize_access = 'FULL'),
			(SELECT count(*) FROM role_pii_permissions WHERE is_active AND detokenize_access = 'MASKED'),
			(SELECT count(*) FROM role_pii_permissions WHERE is_active AND valid_until IS NOT NULL AND valid_until < now())`,
	).Scan(&st.RolesTotal, &st.RolesActive, &st.PIIFull, &st.PIIMasked, &st.PIIExpired)
	return st, err
}

// ---- Admin write paths ----

func (s *rbacStore) roleID(ctx context.Context, roleCode string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM roles WHERE role_code = $1`, roleCode).Scan(&id)
	return id, err
}

func (s *rbacStore) CreateRole(ctx context.Context, roleCode, roleName, description string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO roles (role_code, role_name, description) VALUES ($1, $2, $3)`,
		roleCode, roleName, nullIfEmpty(description))
	return err
}

func (s *rbacStore) UpdateRole(ctx context.Context, roleCode, roleName, description string, isActive bool) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE roles SET role_name = $2, description = $3, is_active = $4, updated_at = now() WHERE role_code = $1`,
		roleCode, roleName, nullIfEmpty(description), isActive)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type roleListRow struct {
	RoleCode    string `json:"role_code"`
	RoleName    string `json:"role_name"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
}

func (s *rbacStore) ListRoles(ctx context.Context) ([]roleListRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT role_code, role_name, COALESCE(description, ''), is_active FROM roles ORDER BY role_code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []roleListRow{}
	for rows.Next() {
		var r roleListRow
		if err := rows.Scan(&r.RoleCode, &r.RoleName, &r.Description, &r.IsActive); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type endpointPermRow struct {
	EndpointAction string `json:"endpoint_action"`
	Allowed        bool   `json:"allowed"`
	IsActive       bool   `json:"is_active"`
}

func (s *rbacStore) GetEndpointPerms(ctx context.Context, roleCode string) ([]endpointPermRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT rep.endpoint_action, rep.allowed, rep.is_active
		FROM role_endpoint_permissions rep
		JOIN roles r ON r.id = rep.role_id
		WHERE r.role_code = $1
		ORDER BY rep.endpoint_action`, roleCode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []endpointPermRow{}
	for rows.Next() {
		var e endpointPermRow
		if err := rows.Scan(&e.EndpointAction, &e.Allowed, &e.IsActive); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type endpointPermInput struct {
	EndpointAction string `json:"endpoint_action"`
	Allowed        bool   `json:"allowed"`
}

// UpsertEndpointPermissions inserts/updates a set of endpoint permissions for a
// role in a single transaction.
func (s *rbacStore) UpsertEndpointPermissions(ctx context.Context, roleID string, perms []endpointPermInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, p := range perms {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO role_endpoint_permissions (role_id, endpoint_action, allowed, is_active, updated_at)
			VALUES ($1, $2, $3, TRUE, now())
			ON CONFLICT (role_id, endpoint_action)
			DO UPDATE SET allowed = EXCLUDED.allowed, is_active = TRUE, updated_at = now()`,
			roleID, p.EndpointAction, p.Allowed); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

type piiPermRow struct {
	PIIType          string  `json:"pii_type"`
	CanTokenize      bool    `json:"can_tokenize"`
	DetokenizeAccess string  `json:"detokenize_access"`
	MaskChar         string  `json:"mask_char"`
	ValidityPeriod   string  `json:"validity_period"`
	ValidFrom        string  `json:"valid_from"`
	ValidUntil       *string `json:"valid_until"`
	IsActive         bool    `json:"is_active"`
}

func (s *rbacStore) GetPIIPerms(ctx context.Context, roleCode string) ([]piiPermRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.pii_type, p.can_tokenize, p.detokenize_access, p.mask_char, p.validity_period,
		       p.valid_from, p.valid_until, p.is_active
		FROM role_pii_permissions p
		JOIN roles r ON r.id = p.role_id
		WHERE r.role_code = $1
		ORDER BY p.pii_type`, roleCode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []piiPermRow{}
	for rows.Next() {
		var p piiPermRow
		var vf time.Time
		var vu sql.NullTime
		if err := rows.Scan(&p.PIIType, &p.CanTokenize, &p.DetokenizeAccess, &p.MaskChar, &p.ValidityPeriod,
			&vf, &vu, &p.IsActive); err != nil {
			return nil, err
		}
		p.ValidFrom = vf.UTC().Format(time.RFC3339)
		if vu.Valid {
			s := vu.Time.UTC().Format(time.RFC3339)
			p.ValidUntil = &s
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type piiPermInput struct {
	PIIType          string     `json:"pii_type"`
	CanTokenize      bool       `json:"can_tokenize"`
	DetokenizeAccess string     `json:"detokenize_access"`
	MaskChar         string     `json:"mask_char"`
	ValidityPeriod   string     `json:"validity_period"`
	ValidFrom        time.Time  // computed server-side
	ValidUntil       *time.Time // computed server-side (nil = FOREVER)
}

// UpsertPIIPermissions inserts/updates per-PII permissions for a role in one tx.
func (s *rbacStore) UpsertPIIPermissions(ctx context.Context, roleID string, perms []piiPermInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, p := range perms {
		var validUntil interface{}
		if p.ValidUntil != nil {
			validUntil = *p.ValidUntil
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO role_pii_permissions
			    (role_id, pii_type, can_tokenize, detokenize_access, mask_char, validity_period, valid_from, valid_until, is_active, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, now())
			ON CONFLICT (role_id, pii_type)
			DO UPDATE SET can_tokenize = EXCLUDED.can_tokenize,
			              detokenize_access = EXCLUDED.detokenize_access,
			              mask_char = EXCLUDED.mask_char,
			              validity_period = EXCLUDED.validity_period,
			              valid_from = EXCLUDED.valid_from,
			              valid_until = EXCLUDED.valid_until,
			              is_active = TRUE,
			              updated_at = now()`,
			roleID, p.PIIType, p.CanTokenize, p.DetokenizeAccess, p.MaskChar, p.ValidityPeriod, p.ValidFrom, validUntil); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// permAuditEntry is one configuration-change row for permission_audit_logs.
type permAuditEntry struct {
	Actor          string
	Action         string
	RoleCode       string
	EndpointAction string
	PIIType        string
	OldValue       []byte // JSON or nil
	NewValue       []byte // JSON or nil
	Reason         string
	Decision       string
	IP             string
}

func (s *rbacStore) InsertPermissionAuditLog(ctx context.Context, e permAuditEntry) error {
	var oldV, newV interface{}
	if len(e.OldValue) > 0 {
		oldV = e.OldValue
	}
	if len(e.NewValue) > 0 {
		newV = e.NewValue
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO permission_audit_logs
		    (actor, action, role_code, endpoint_action, pii_type, old_value, new_value, reason, decision, ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		nullIfEmpty(e.Actor), e.Action, nullIfEmpty(e.RoleCode), nullIfEmpty(e.EndpointAction),
		nullIfEmpty(e.PIIType), oldV, newV, nullIfEmpty(e.Reason), e.Decision, nullIfEmpty(e.IP))
	return err
}
