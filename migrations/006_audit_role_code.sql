-- migrations/006_audit_role_code.sql
-- Record the RBAC role on each runtime audit row. Populated only when
-- PERMISSION_CHECK_ENABLED is on and an X-Role-Code was presented; NULL
-- otherwise. Additive + idempotent — does not alter existing rows or behavior.
ALTER TABLE pii_audit_logs ADD COLUMN IF NOT EXISTS role_code TEXT;
CREATE INDEX IF NOT EXISTS idx_pii_audit_logs_role_code ON pii_audit_logs (role_code);
