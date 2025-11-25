package models

import (
	"database/sql"
	"fmt"
)

// PiiTokenRow is a lightweight struct representing a row in pii_tokens used by v3
type PiiTokenRow struct {
	ID             int64
	EncryptedValue []byte
	BlindIndex     string
	FPT            string
	DataType       string
	TenantID       sql.NullString
	FPEKeyVersion  sql.NullString
	CreatedAt      string
}

// GetByBlindIndexTenant returns tenant-scoped row (tenantID may be empty string -> matches NULL)
func (s *Store) GetByBlindIndexTenant(tenantID, blind string) (*PiiTokenRow, error) {
	row := s.db.QueryRow(`
        SELECT id, encrypted_value, blind_index, fpt, data_type, tenant_id, fpe_key_version, created_at
        FROM pii_tokens
        WHERE ( ($1 = '' AND tenant_id IS NULL) OR (tenant_id = $1) )
          AND blind_index = $2
        LIMIT 1
    `, tenantID, blind)

	var r PiiTokenRow
	var tenant sql.NullString
	var fpe sql.NullString
	err := row.Scan(&r.ID, &r.EncryptedValue, &r.BlindIndex, &r.FPT, &r.DataType, &tenant, &fpe, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}
	r.TenantID = tenant
	r.FPEKeyVersion = fpe
	return &r, nil
}

// GetByFPTTenant returns tenant-scoped row for given fpt
func (s *Store) GetByFPTTenant(tenantID, fpt string) (*PiiTokenRow, error) {
	row := s.db.QueryRow(`
        SELECT id, encrypted_value, blind_index, fpt, data_type, tenant_id, fpe_key_version, created_at
        FROM pii_tokens
        WHERE ( ($1 = '' AND tenant_id IS NULL) OR (tenant_id = $1) )
          AND fpt = $2
        LIMIT 1
    `, tenantID, fpt)

	var r PiiTokenRow
	var tenant sql.NullString
	var fpe sql.NullString
	err := row.Scan(&r.ID, &r.EncryptedValue, &r.BlindIndex, &r.FPT, &r.DataType, &tenant, &fpe, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}
	r.TenantID = tenant
	r.FPEKeyVersion = fpe
	return &r, nil
}

// InsertTokenTenant inserts a tenant-scoped token. tenantID=="" writes NULL into tenant_id.
func (s *Store) InsertTokenTenant(encValue []byte, blindIndex, fpt, dataType, tenantID, fpeKeyVersion string) (*PiiTokenRow, error) {
    // Use ON CONFLICT DO NOTHING so concurrent inserts don't fail with unique constraint.
    // We try to return id, created_at if we inserted; if another transaction inserted,
    // RETURNING will return no rows and QueryRow().Scan will return sql.ErrNoRows.
    row := s.db.QueryRow(`
        INSERT INTO pii_tokens (encrypted_value, blind_index, fpt, data_type, tenant_id, fpe_key_version)
        VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''))
        ON CONFLICT (blind_index) DO NOTHING
        RETURNING id, created_at
    `, encValue, blindIndex, fpt, dataType, tenantID, fpeKeyVersion)

    var id int64
    var createdAt string
    if err := row.Scan(&id, &createdAt); err != nil {
        if err == sql.ErrNoRows {
            // No row inserted — concurrent insert happened. Caller will SELECT the existing row.
            return nil, nil
        }
        return nil, fmt.Errorf("insert scan: %w", err)
    }

    return &PiiTokenRow{
        ID:             id,
        EncryptedValue: encValue,
        BlindIndex:     blindIndex,
        FPT:            fpt,
        DataType:       dataType,
        TenantID:       sql.NullString{String: tenantID, Valid: tenantID != ""},
        FPEKeyVersion:  sql.NullString{String: fpeKeyVersion, Valid: fpeKeyVersion != ""},
        CreatedAt:      createdAt,
    }, nil
}
