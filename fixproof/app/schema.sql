-- fixproof Phase 0 schema (a trimmed subset of docs/ARCHITECTURE.md section 8).
-- Only the tables the execution core writes to in Phase 0.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS replay_artifacts (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,   -- e.g. cve-2021-41773-path-traversal
    kind        TEXT NOT NULL DEFAULT 'nuclei',
    body        TEXT NOT NULL,          -- the template source, for provenance
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per (product, version) we can stand up and test against.
CREATE TABLE IF NOT EXISTS snapshots (
    id          BIGSERIAL PRIMARY KEY,
    product     TEXT NOT NULL,          -- httpd
    ref         TEXT NOT NULL,          -- image tag, e.g. 2.4.49
    kind        TEXT NOT NULL DEFAULT 'image',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (product, ref)
);

-- One row per (artifact x snapshot x attempt). This is the raw evidence that the
-- verdict engine (Phase 2) will later read. In Phase 0 we just record it.
CREATE TABLE IF NOT EXISTS replay_runs (
    id             BIGSERIAL PRIMARY KEY,
    batch_id       UUID NOT NULL,          -- groups the versions tested in one request
    artifact_name  TEXT NOT NULL,
    product        TEXT NOT NULL,
    version        TEXT NOT NULL,
    outcome        TEXT NOT NULL,          -- pass | fail | error
    matched        BOOLEAN,                -- did the state oracle match?
    evidence       JSONB,                  -- raw nuclei result / error detail
    duration_ms    INTEGER,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS replay_runs_batch_idx ON replay_runs (batch_id);

-- One row per triage decision: did the candidate's fix cover the new report?
CREATE TABLE IF NOT EXISTS verdicts (
    id               BIGSERIAL PRIMARY KEY,
    product          TEXT NOT NULL,
    new_template     TEXT NOT NULL,       -- the incoming report's PoC
    candidate_template TEXT,              -- the earlier report we compare against
    candidate_fixed_in TEXT,             -- version where the candidate was fixed
    label            TEXT NOT NULL,       -- DUPLICATE | BYPASS | NOT_REPRODUCED | ABSTAIN
    evidence         JSONB,               -- the pre-fix and post-fix runs
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
