-- migrations/009_seed_dob_pii_permission.sql
-- Seed the DATE_OF_BIRTH PII permission for SUPER_ADMIN on EXISTING databases.
-- Migration 005 already ran on existing infra and will not re-run, so this
-- idempotent insert grants SUPER_ADMIN full DATE_OF_BIRTH access without
-- touching any other role or type. Fresh installs get this row from 005 itself.
-- No schema change: pii_tokens.data_type / role_pii_permissions.pii_type are
-- unconstrained TEXT, so DATE_OF_BIRTH tokens/permissions are already valid.

INSERT INTO role_pii_permissions (role_id, pii_type, can_tokenize, detokenize_access, validity_period, valid_until)
SELECT r.id, 'DATE_OF_BIRTH', TRUE, 'FULL', 'FOREVER', NULL
FROM roles r
WHERE r.role_code = 'SUPER_ADMIN'
ON CONFLICT (role_id, pii_type) DO NOTHING;
