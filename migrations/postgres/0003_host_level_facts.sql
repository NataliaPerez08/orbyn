-- v0.3 host-level discovery (PostgreSQL).
-- Filesystem inventory and running host services; CPU/RAM capacity lands in
-- the asset_capacity table reserved since the initial schema.

CREATE TABLE IF NOT EXISTS asset_filesystems (
    asset_id     TEXT NOT NULL REFERENCES assets(id),
    device       TEXT,
    mount        TEXT NOT NULL,
    fs_type      TEXT,
    size_kb      BIGINT NOT NULL,
    used_kb      BIGINT,
    available_kb BIGINT,
    used_pct     BIGINT,
    PRIMARY KEY (asset_id, mount)
);

CREATE INDEX IF NOT EXISTS idx_asset_filesystems_asset
    ON asset_filesystems (asset_id);

CREATE TABLE IF NOT EXISTS asset_running_services (
    asset_id    TEXT NOT NULL REFERENCES assets(id),
    name        TEXT NOT NULL,
    state       TEXT,
    description TEXT,
    PRIMARY KEY (asset_id, name)
);
