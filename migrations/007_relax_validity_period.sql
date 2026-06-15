-- migrations/007_relax_validity_period.sql
-- Allow arbitrary "<N>_DAYS" validity periods (custom days) in addition to
-- FOREVER. The fixed-set CHECK is dropped; validity is enforced via valid_until
-- (computed server-side at save time), so validity_period is now just a
-- self-describing label. Additive + idempotent.
ALTER TABLE role_pii_permissions DROP CONSTRAINT IF EXISTS chk_validity_period;
