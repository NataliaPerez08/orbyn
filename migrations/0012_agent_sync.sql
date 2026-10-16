-- v1.6 remote profiling: server-side agent enrollment and agent-side
-- sync cursor. Tokens are stored as hex SHA-256 hashes; the plaintext
-- token is shown once at enrollment and never persisted. agent_state is
-- a tiny key-value store (the agent's sync cursor).

CREATE TABLE IF NOT EXISTS agent_tokens (
    asset_id    TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
