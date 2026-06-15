-- migrations/008_pii_mask_char.sql
-- Per-(role, pii_type) mask character for MASKED detokenize: 'X' (default) or '*'.
-- Only the fill character changes; the keep-last-N masking shape stays in code.
-- Additive + idempotent.
ALTER TABLE role_pii_permissions ADD COLUMN IF NOT EXISTS mask_char TEXT NOT NULL DEFAULT 'X';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_mask_char'
    ) THEN
        ALTER TABLE role_pii_permissions
            ADD CONSTRAINT chk_mask_char CHECK (mask_char IN ('X', '*'));
    END IF;
END$$;
