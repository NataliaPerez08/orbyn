-- v1.0 operational audit trail for mutating CLI operations.

CREATE TABLE IF NOT EXISTS audit_events (
    id          TEXT PRIMARY KEY,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    details     TEXT,
    error       TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_started
    ON audit_events (started_at DESC);
