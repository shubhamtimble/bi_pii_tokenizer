-- migrations/001_create_pii_tokens.sql
CREATE TABLE IF NOT EXISTS pii_tokens (
    id SERIAL PRIMARY KEY,
    encrypted_value BYTEA NOT NULL,   -- stores base64 string bytes (or ciphertext bytes)
    blind_index TEXT NOT NULL,
    fpt TEXT NOT NULL,
    data_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Unique indexes
CREATE UNIQUE INDEX IF NOT EXISTS uq_pii_tokens_blind_index ON pii_tokens (blind_index);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pii_tokens_fpt ON pii_tokens (fpt);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pii_tokens_encrypted_value ON pii_tokens (encrypted_value);
