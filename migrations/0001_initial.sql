-- Initial Orbyn schema.
-- Reserve capacity/utilization/dependency tables now so later migrations can
-- evolve them without breaking the v0.1 shape.

CREATE TABLE IF NOT EXISTS assets (
    id            TEXT PRIMARY KEY,
    ip            TEXT NOT NULL UNIQUE,
    hostname      TEXT,
    device_class  TEXT,
    os_name       TEXT,
    os_version    TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    asset_id      TEXT NOT NULL REFERENCES assets(id),
    proto         TEXT NOT NULL,
    port          INTEGER NOT NULL,
    name          TEXT,
    state         TEXT NOT NULL,
    banner        TEXT,
    PRIMARY KEY (asset_id, proto, port)
);

CREATE TABLE IF NOT EXISTS discovery_jobs (
    id            TEXT PRIMARY KEY,
    collector     TEXT NOT NULL,
    targets       TEXT NOT NULL,
    status        TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    error         TEXT
);

-- Capacity/utilization/dependencies are reserved for upcoming milestones.
CREATE TABLE IF NOT EXISTS asset_capacity (
    asset_id      TEXT PRIMARY KEY REFERENCES assets(id),
    cpu_model     TEXT,
    cpu_sockets   INTEGER,
    cpu_cores     INTEGER,
    cpu_threads   INTEGER,
    ram_total_mb  INTEGER,
    collected_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metric_samples (
    id                TEXT PRIMARY KEY,
    asset_id          TEXT NOT NULL REFERENCES assets(id),
    sampled_at        TEXT NOT NULL,
    cpu_usage_percent REAL,
    ram_used_mb       INTEGER,
    ram_available_mb  INTEGER,
    swap_used_mb      INTEGER,
    load_1m           REAL,
    load_5m           REAL,
    load_15m          REAL
);

CREATE INDEX IF NOT EXISTS idx_metric_samples_asset_time
    ON metric_samples (asset_id, sampled_at);

CREATE TABLE IF NOT EXISTS dependencies (
    source_asset_id  TEXT NOT NULL REFERENCES assets(id),
    target_asset_id  TEXT NOT NULL REFERENCES assets(id),
    proto            TEXT NOT NULL,
    port             INTEGER NOT NULL,
    evidence_source  TEXT NOT NULL,
    confidence       REAL NOT NULL DEFAULT 1.0,
    confirmed        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (source_asset_id, target_asset_id, proto, port)
);