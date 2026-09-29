-- v1.2 historical metric ingestion (PostgreSQL): one sample per asset and
-- instant, so importing the same window twice (e.g. a re-run of
-- `orbyn prometheus import`) is idempotent instead of duplicating rows.
-- Pre-existing duplicates are collapsed to their lowest id before the
-- index is created.

DELETE FROM metric_samples
WHERE id NOT IN (
    SELECT MIN(id) FROM metric_samples GROUP BY asset_id, sampled_at
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_metric_samples_asset_instant
    ON metric_samples (asset_id, sampled_at);
