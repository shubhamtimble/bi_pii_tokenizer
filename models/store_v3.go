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
	FPEKeyVersion  sql.NullString
	CreatedAt      string
}

// GetByBlindIndexV3 returns a row for v3 by blind index.
func (s *Store) GetByBlindIndexV3(blind string) (*PiiTokenRow, error) {
	row := s.db.QueryRow(`
        SELECT id, encrypted_value, blind_index, fpt, data_type, fpe_key_version, created_at
        FROM pii_tokens
        WHERE blind_index = $1
        LIMIT 1
    `, blind)

	var r PiiTokenRow
	var fpe sql.NullString
	err := row.Scan(&r.ID, &r.EncryptedValue, &r.BlindIndex, &r.FPT, &r.DataType, &fpe, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}
	r.FPEKeyVersion = fpe
	return &r, nil
}

// GetByFPTV3 returns a row for v3 by fpt.
func (s *Store) GetByFPTV3(fpt string) (*PiiTokenRow, error) {
	row := s.db.QueryRow(`
        SELECT id, encrypted_value, blind_index, fpt, data_type, fpe_key_version, created_at
        FROM pii_tokens
        WHERE fpt = $1
        LIMIT 1
    `, fpt)

	var r PiiTokenRow
	var fpe sql.NullString
	err := row.Scan(&r.ID, &r.EncryptedValue, &r.BlindIndex, &r.FPT, &r.DataType, &fpe, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}
	r.FPEKeyVersion = fpe
	return &r, nil
}

// InsertTokenV3 inserts a v3 token and stores the fpe_key_version.
func (s *Store) InsertTokenV3(encValue []byte, blindIndex, fpt, dataType, fpeKeyVersion string) (*PiiTokenRow, error) {
    // Use ON CONFLICT DO NOTHING so concurrent inserts don't fail with unique constraint.
    // We try to return id, created_at if we inserted; if another transaction inserted,
    // RETURNING will return no rows and QueryRow().Scan will return sql.ErrNoRows.
    row := s.db.QueryRow(`
        INSERT INTO pii_tokens (encrypted_value, blind_index, fpt, data_type, fpe_key_version)
        VALUES ($1, $2, $3, $4, NULLIF($5, ''))
        ON CONFLICT (blind_index) DO NOTHING
        RETURNING id, created_at
    `, encValue, blindIndex, fpt, dataType, fpeKeyVersion)

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
        FPEKeyVersion:  sql.NullString{String: fpeKeyVersion, Valid: fpeKeyVersion != ""},
        CreatedAt:      createdAt,
    }, nil
}
