-- v1.2 migration planner (PostgreSQL dialect).
-- A plan is a reproducible artifact, not a query target: the scalar
-- summary lives in columns, the detail (provenance, factors,
-- recommendation, targets, blockers, assumptions) in JSON. Plans are
-- append-only; re-planning inserts a new row.

CREATE TABLE IF NOT EXISTS migration_plans (
    id                TEXT PRIMARY KEY,
    application_id    TEXT NOT NULL REFERENCES applications(id),
    created_at        TEXT NOT NULL,
    provenance        TEXT NOT NULL,
    readiness         BIGINT NOT NULL,
    readiness_factors TEXT NOT NULL,
    recommendation    TEXT NOT NULL,
    wave              BIGINT,
    targets           TEXT NOT NULL,
    blockers          TEXT NOT NULL,
    assumptions       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_migration_plans_application
    ON migration_plans (application_id);
