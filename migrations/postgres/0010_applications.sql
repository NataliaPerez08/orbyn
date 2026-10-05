-- v1.1 application intelligence (PostgreSQL).
-- Applications become persisted entities: inferred groups are stored with
-- per-member confidence and evidence, and manual curation overrides
-- inference. Connection rows gain an upsert counter so repeated
-- communication becomes measurable evidence.

ALTER TABLE asset_connections
    ADD COLUMN observation_count BIGINT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS applications (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    source      TEXT NOT NULL,
    confidence  DOUBLE PRECISION NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS application_members (
    application_id TEXT NOT NULL REFERENCES applications(id),
    asset_id       TEXT NOT NULL REFERENCES assets(id),
    source         TEXT NOT NULL,
    confidence     DOUBLE PRECISION NOT NULL,
    evidence       TEXT NOT NULL,
    is_excluded    BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (application_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_application_members_asset
    ON application_members (asset_id);
