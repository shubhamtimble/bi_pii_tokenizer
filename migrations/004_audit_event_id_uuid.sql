-- migrations/004_audit_event_id_uuid.sql
-- Add a public UUID `event_id` to pii_audit_logs. The internal BIGSERIAL `id`
-- stays — used as the stable, monotonically increasing cursor for
-- newest-first pagination. The UUID is the value exposed to API clients in
-- the `event_id` field of the audit/events response.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Add the column nullable so we can backfill safely.
ALTER TABLE pii_audit_logs ADD COLUMN IF NOT EXISTS event_id UUID;

-- Backfill existing rows with random UUIDs.
UPDATE pii_audit_logs SET event_id = gen_random_uuid() WHERE event_id IS NULL;

-- Lock down: future inserts auto-generate; column is mandatory.
ALTER TABLE pii_audit_logs ALTER COLUMN event_id SET DEFAULT gen_random_uuid();
ALTER TABLE pii_audit_logs ALTER COLUMN event_id SET NOT NULL;

-- Unique index so event_id can be a public-facing primary identifier.
CREATE UNIQUE INDEX IF NOT EXISTS idx_pii_audit_logs_event_id ON pii_audit_logs (event_id);
