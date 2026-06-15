-- migrations/005_create_rbac_permission_tables.sql
-- RBAC permission layer (additive). These tables are only consulted when
-- PERMISSION_CHECK_ENABLED=true; with the flag false the service ignores them
-- entirely and behaves exactly as before. All statements are idempotent so the
-- migration is safe to (re)apply against existing client infra.
--
-- pii_type values use the canonical codes the code already stores in
-- pii_tokens.data_type: PAN, AADHAAR, MOBILE, PHONE, EMAIL, DL, PASSPORT, VOTERID.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_code TEXT NOT NULL UNIQUE,
    role_name TEXT NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS role_endpoint_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id),
    endpoint_action TEXT NOT NULL,
    allowed BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_role_endpoint_permission UNIQUE(role_id, endpoint_action)
);

CREATE TABLE IF NOT EXISTS role_pii_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id),
    pii_type TEXT NOT NULL,
    can_tokenize BOOLEAN NOT NULL DEFAULT FALSE,
    detokenize_access TEXT NOT NULL DEFAULT 'NONE',
    validity_period TEXT NOT NULL DEFAULT 'FOREVER',
    valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_role_pii_permission UNIQUE(role_id, pii_type),
    CONSTRAINT chk_detokenize_access CHECK (detokenize_access IN ('NONE', 'MASKED', 'FULL')),
    CONSTRAINT chk_validity_period CHECK (validity_period IN ('15_DAYS', '30_DAYS', '60_DAYS', '90_DAYS', '180_DAYS', '1_YEAR', 'FOREVER'))
);

CREATE TABLE IF NOT EXISTS permission_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL DEFAULT gen_random_uuid(),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT,
    action TEXT NOT NULL,
    role_code TEXT,
    endpoint_action TEXT,
    pii_type TEXT,
    old_value JSONB,
    new_value JSONB,
    reason TEXT,
    decision TEXT NOT NULL,
    ip TEXT
);

CREATE INDEX IF NOT EXISTS idx_roles_role_code ON roles(role_code);
CREATE INDEX IF NOT EXISTS idx_role_endpoint_permissions_role_action ON role_endpoint_permissions(role_id, endpoint_action);
CREATE INDEX IF NOT EXISTS idx_role_pii_permissions_role_pii ON role_pii_permissions(role_id, pii_type);
CREATE INDEX IF NOT EXISTS idx_role_pii_permissions_validity ON role_pii_permissions(valid_from, valid_until, is_active);
CREATE INDEX IF NOT EXISTS idx_permission_audit_logs_occurred_at ON permission_audit_logs(occurred_at);
CREATE INDEX IF NOT EXISTS idx_permission_audit_logs_role_code ON permission_audit_logs(role_code);
CREATE INDEX IF NOT EXISTS idx_permission_audit_logs_action ON permission_audit_logs(action);

-- ---------------------------------------------------------------------------
-- Bootstrap admin role. SUPER_ADMIN has every endpoint permission plus FULL
-- detokenize on all PII types (FOREVER). It lets you manage roles/permissions
-- immediately even with PERMISSION_CHECK_ENABLED=true. Rename or deactivate it
-- after creating your real roles. All inserts are idempotent.
-- ---------------------------------------------------------------------------
INSERT INTO roles (role_code, role_name, description)
VALUES ('SUPER_ADMIN', 'Super Admin',
        'Bootstrap admin: all endpoint permissions + FULL detokenize on every PII type. Rename/lock down after setup.')
ON CONFLICT (role_code) DO NOTHING;

INSERT INTO role_endpoint_permissions (role_id, endpoint_action, allowed)
SELECT r.id, a.action, TRUE
FROM roles r
CROSS JOIN (VALUES ('TOKENIZE'), ('DETOKENIZE'), ('AUDIT_READ'),
                   ('ROLE_MANAGE'), ('PERMISSION_MANAGE')) AS a(action)
WHERE r.role_code = 'SUPER_ADMIN'
ON CONFLICT (role_id, endpoint_action) DO NOTHING;

INSERT INTO role_pii_permissions (role_id, pii_type, can_tokenize, detokenize_access, validity_period, valid_until)
SELECT r.id, t.pii_type, TRUE, 'FULL', 'FOREVER', NULL
FROM roles r
CROSS JOIN (VALUES ('PAN'), ('AADHAAR'), ('MOBILE'), ('PHONE'),
                   ('EMAIL'), ('DL'), ('PASSPORT'), ('VOTERID')) AS t(pii_type)
WHERE r.role_code = 'SUPER_ADMIN'
ON CONFLICT (role_id, pii_type) DO NOTHING;
