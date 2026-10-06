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
