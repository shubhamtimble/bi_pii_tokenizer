-- migrations/002_create_pii_audit_logs.sql
-- Append-only audit table populated by the AuditLogger background worker
-- via pq.CopyIn. One row per tokenize/detokenize/bulk-tokenize call (legacy
-- v1 and v4). Plaintext PII and blind indexes are deliberately never written.
CREATE TABLE IF NOT EXISTS pii_audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    req_id      TEXT,
    action      TEXT NOT NULL,
    version     TEXT NOT NULL,
    pii_type    TEXT,
    fpt         TEXT,
    status      TEXT NOT NULL,
    latency_ms  BIGINT,
    error       TEXT,
    remote_ip   TEXT
);

CREATE INDEX IF NOT EXISTS idx_pii_audit_logs_ts ON pii_audit_logs (ts);
CREATE INDEX IF NOT EXISTS idx_pii_audit_logs_fpt ON pii_audit_logs (fpt);
CREATE INDEX IF NOT EXISTS idx_pii_audit_logs_action_status ON pii_audit_logs (action, status);
