package models

import (
	"database/sql"
	"errors"
	"time"
)

type PiiToken struct {
	ID             int64
	EncryptedValue []byte
	BlindIndex     string
	FPT            string
	DataType       string
	CreatedAt      time.Time
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Export DB handle safely
func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) GetByBlindIndex(bi string) (*PiiToken, error) {
	row := s.db.QueryRow(`SELECT id, encrypted_value, blind_index, fpt, data_type, created_at FROM pii_tokens WHERE blind_index = $1`, bi)
	var pt PiiToken
	err := row.Scan(&pt.ID, &pt.EncryptedValue, &pt.BlindIndex, &pt.FPT, &pt.DataType, &pt.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &pt, nil
}

func (s *Store) GetByFPT(fpt string) (*PiiToken, error) {
	row := s.db.QueryRow(`SELECT id, encrypted_value, blind_index, fpt, data_type, created_at FROM pii_tokens WHERE fpt = $1`, fpt)
	var pt PiiToken
	err := row.Scan(&pt.ID, &pt.EncryptedValue, &pt.BlindIndex, &pt.FPT, &pt.DataType, &pt.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &pt, nil
}

var ErrDuplicate = errors.New("duplicate")

func (s *Store) InsertToken(enc []byte, blindIndex, fpt, dataType string) (*PiiToken, error) {
	row := s.db.QueryRow(
		`INSERT INTO pii_tokens (encrypted_value, blind_index, fpt, data_type)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, created_at`,
		enc, blindIndex, fpt, dataType,
	)
	var id int64
	var createdAt time.Time
	if err := row.Scan(&id, &createdAt); err != nil {
		return nil, err
	}
	return &PiiToken{
		ID:             id,
		EncryptedValue: enc,
		BlindIndex:     blindIndex,
		FPT:            fpt,
		DataType:       dataType,
		CreatedAt:      createdAt,
	}, nil
}

