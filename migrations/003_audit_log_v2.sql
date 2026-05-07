-- migrations/003_audit_log_v2.sql
-- Audit log v2: adds actor / reason / value_hash / decision; renames ts→occurred_at
-- and remote_ip→ip; suffixes legacy error rows with `.failed` so the action enum is
-- consistent across pre- and post-migration data.

-- 1) Rename existing columns
ALTER TABLE pii_audit_logs RENAME COLUMN ts        TO occurred_at;
ALTER TABLE pii_audit_logs RENAME COLUMN remote_ip TO ip;

-- 2) Add new columns (nullable so we can backfill safely)
ALTER TABLE pii_audit_logs ADD COLUMN IF NOT EXISTS actor      TEXT;
ALTER TABLE pii_audit_logs ADD COLUMN IF NOT EXISTS reason     TEXT;
ALTER TABLE pii_audit_logs ADD COLUMN IF NOT EXISTS value_hash TEXT;
ALTER TABLE pii_audit_logs ADD COLUMN IF NOT EXISTS decision   TEXT;

-- 3) Backfill existing rows
UPDATE pii_audit_logs SET actor = 'system' WHERE actor IS NULL;

UPDATE pii_audit_logs SET decision =
    CASE
        WHEN status = 'success' THEN 'success'
        WHEN status = 'error'   THEN 'failure'
        ELSE 'failure'
    END
WHERE decision IS NULL;

-- 4) Suffix .failed on legacy error rows so the action enum is consistent
UPDATE pii_audit_logs SET action = action || '.failed'
WHERE status = 'error' AND action NOT LIKE '%.failed';

-- 5) Drop the now-subsumed status column
ALTER TABLE pii_audit_logs DROP COLUMN IF EXISTS status;

-- 6) decision is required going forward; actor/reason stay nullable per spec
ALTER TABLE pii_audit_logs ALTER COLUMN decision SET NOT NULL;

-- 7) Refresh indexes
DROP INDEX IF EXISTS idx_pii_audit_logs_ts;
DROP INDEX IF EXISTS idx_pii_audit_logs_action_status;
CREATE INDEX IF NOT EXISTS idx_pii_audit_logs_occurred_at      ON pii_audit_logs (occurred_at);
CREATE INDEX IF NOT EXISTS idx_pii_audit_logs_fpt              ON pii_audit_logs (fpt);
CREATE INDEX IF NOT EXISTS idx_pii_audit_logs_actor            ON pii_audit_logs (actor);
CREATE INDEX IF NOT EXISTS idx_pii_audit_logs_reason           ON pii_audit_logs (reason);
CREATE INDEX IF NOT EXISTS idx_pii_audit_logs_action_decision  ON pii_audit_logs (action, decision);
