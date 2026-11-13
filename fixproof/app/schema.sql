-- Tables used by replay, candidate search and triage.

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Incoming and historical reports. Today these are real public CVE
-- descriptions pulled from OSV; later they are hunter-written reports. The
-- candidate proposer (app/search.py) ranks over this table. `search` is a
-- generated full-text column; a trigram index handles fuzzy lexical overlap.
CREATE TABLE IF NOT EXISTS reports (
    id           BIGSERIAL PRIMARY KEY,
    source       TEXT NOT NULL,            -- osv | manual | ...
    external_id  TEXT UNIQUE,              -- e.g. CVE-2021-41773
    product      TEXT,
    text         TEXT NOT NULL,
    published_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    search       tsvector GENERATED ALWAYS AS (to_tsvector('english', text)) STORED
);
CREATE INDEX IF NOT EXISTS reports_search_idx ON reports USING gin (search);
CREATE INDEX IF NOT EXISTS reports_trgm_idx ON reports USING gin (text gin_trgm_ops);

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
-- verdict engine reads.
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
