-- v0.4 dependency mapping (PostgreSQL).
-- Raw active-connection observations feed the dependency edges: the store
-- reconciles each remote endpoint against known assets and upserts an edge
-- with evidence `active-connections`.

CREATE TABLE IF NOT EXISTS asset_connections (
    asset_id    TEXT NOT NULL REFERENCES assets(id),
    proto       TEXT NOT NULL,
    local_ip    TEXT,
    local_port  BIGINT,
    remote_ip   TEXT NOT NULL,
    remote_port BIGINT NOT NULL,
    process     TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (asset_id, proto, remote_ip, remote_port)
);

CREATE INDEX IF NOT EXISTS idx_asset_connections_asset
    ON asset_connections (asset_id);

CREATE INDEX IF NOT EXISTS idx_dependencies_source
    ON dependencies (source_asset_id);

CREATE INDEX IF NOT EXISTS idx_dependencies_target
    ON dependencies (target_asset_id);
