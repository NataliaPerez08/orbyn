-- v0.2 inventory enrichment.
-- Adds inventory annotation to assets, interface collection, and per-job
-- outcome counters for the job-history CLI.

ALTER TABLE assets ADD COLUMN environment TEXT;
ALTER TABLE assets ADD COLUMN owner TEXT;
ALTER TABLE assets ADD COLUMN criticality TEXT;
ALTER TABLE assets ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS asset_interfaces (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL REFERENCES assets(id),
    name        TEXT,
    mac         TEXT,
    ip          TEXT,
    vendor      TEXT,
    mtu         INTEGER,
    if_index    INTEGER,
    is_up       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_asset_interfaces_asset ON asset_interfaces (asset_id);

ALTER TABLE discovery_jobs ADD COLUMN assets_found INTEGER;
ALTER TABLE discovery_jobs ADD COLUMN services_found INTEGER;

CREATE INDEX IF NOT EXISTS idx_discovery_jobs_started ON discovery_jobs (started_at DESC);