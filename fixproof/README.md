# FixProof — Phases 0–1

The execution core plus the triage verdict. FixProof stands up Apache httpd at
several versions, replays a PoC against each on an egress-less Docker network, and
decides whether a new report is a duplicate of an earlier one by running its PoC
*before* and *after* the earlier fix — not by comparing text.

## Requires

- Docker (running)
- [uv](https://docs.astral.sh/uv/)

## Run

```bash
docker compose up -d          # Postgres (pgvector) on host port 55432
uv sync
uv run uvicorn app.main:app --port 8099
```

In another shell:

```bash
curl -s -X POST localhost:8099/replays/run \
  -H 'content-type: application/json' \
  -d '{"product":"httpd","template":"cve-2021-41773","versions":["2.4.49","2.4.50","2.4.51"]}' | python3 -m json.tool
```

Expected:

| version | outcome | meaning |
|---|---|---|
| 2.4.49 | pass | PoC reproduces (vulnerable) |
| 2.4.50 | fail | the fix stopped it |
| 2.4.51 | fail | still fixed |

Fetch a stored batch: `GET /replays/{batch_id}`.

## Triage (the verdict)

Decide whether a new report is a duplicate of an earlier one. The new PoC is run on
the last version before the candidate's fix (the control) and on the first version
with it:

```bash
# A real bypass: CVE-2021-42013 still works after the CVE-2021-41773 fix -> BYPASS
curl -s -X POST localhost:8099/triage -H 'content-type: application/json' -d '{
  "product":"httpd","new_template":"cve-2021-42013","candidate_template":"cve-2021-41773",
  "candidate_pre_fix":"2.4.49","candidate_fixed_in":"2.4.50"}' | python3 -m json.tool
```

| new report | candidate (fixed in) | verdict |
|---|---|---|
| cve-2021-42013 (bypass) | cve-2021-41773 (2.4.50) | **BYPASS** — still works with the fix |
| cve-2021-41773 (itself) | cve-2021-41773 (2.4.50) | **DUPLICATE** — the fix stops it |

Both reports read the same `/etc/passwd` and look almost identical in text. A
similarity-based deduper merges them; execution tells them apart.

## Candidate search (propose, don't decide)

Pull real public CVE descriptions from OSV, then rank them against an incoming
report. Search only narrows the field; execution decides.

```bash
curl -s -X POST localhost:8099/reports/ingest -d '{}'     # loads 6 real httpd CVEs from OSV
curl -s -X POST localhost:8099/search -H 'content-type: application/json' \
  -d '{"text":"path traversal in Apache using encoded ../ to read /etc/passwd"}'
```

The two traversal CVEs (41773, 42013) score ~1.8; the SSRF, request-smuggling and
NULL-deref CVEs score ~0.15.

### The full loop in one call

`/triage/auto` takes an incoming report (prose + its PoC), lets search pick the
candidate, then runs the fix-differential against it:

```bash
curl -s -X POST localhost:8099/triage/auto -H 'content-type: application/json' -d '{
  "text":"Apache path traversal: double-encoded ../ reads /etc/passwd outside the web root",
  "new_template":"cve-2021-42013"}'
# -> chosen_candidate CVE-2021-41773 (score ~1.84), verdict BYPASS
```

## Scan a version ladder ("is it already fixed?")

```bash
curl -s -X POST localhost:8099/scan -H 'content-type: application/json' \
  -d '{"template":"cve-2021-41773","versions":["2.4.49","2.4.50","2.4.51"]}'
# -> status ALREADY_FIXED, last_vulnerable 2.4.49, fixed_in 2.4.50
```

## Not Apache-specific

A second real product, Grafana (CVE-2021-43798), runs through the same engine with
only a target spec (`app/targets.py`) and a template added — no code changes:

```bash
curl -s -X POST localhost:8099/scan -H 'content-type: application/json' \
  -d '{"product":"grafana","template":"cve-2021-43798","versions":["8.3.0","8.3.1"]}'
# -> ALREADY_FIXED, last_vulnerable 8.3.0, fixed_in 8.3.1
```

Adding a product = one `TargetSpec` (image repo, port, optional config mount) + a
PoC template.

A third product, **MLflow (CVE-2023-1177)**, is a local file read reached through a
three-step model-registry flow — nothing like the httpd/Grafana URL traversals. It
has no official versioned image, so the runner *builds* it from
`targets/mlflow/Dockerfile` at the requested version instead of pulling it (the
`TargetSpec` just adds a `build_context` and `build_arg`); the engine is otherwise
untouched.

```bash
curl -s -X POST localhost:8099/scan -H 'content-type: application/json' \
  -d '{"product":"mlflow","template":"cve-2023-1177","versions":["2.1.1","2.2.1"]}'
# -> ALREADY_FIXED, last_vulnerable 2.1.1, fixed_in 2.2.1
```

## Test

```bash
uv run pytest -s
```

## Layout

```
app/
  main.py      FastAPI: POST /replays/run, GET /replays/{batch_id}
  runner.py    starts a target + nuclei container on the isolated network, parses the oracle
  db.py        psycopg3 helpers
  schema.sql   replay_runs and friends
  config.py    env-driven settings
replays/
  cve-2021-41773.yaml      the PoC as a Nuclei template (the state oracle)
targets/httpd-cve-2021-41773/
  httpd.conf   deliberately vulnerable Apache config (mounted into the throwaway target)
```

## Notes

- Targets and the nuclei runner share an `--internal` Docker network, so a PoC has
  no internet access. Stronger sandboxing (gVisor, cap-drop) comes in Phase 2.
- Host port 55432 avoids a clash with a local Postgres on 5432. Override with
  `FIXPROOF_DATABASE_URL`.
