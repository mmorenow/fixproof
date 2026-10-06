# FixProof — Phase 0

The execution core. One API call stands up Apache httpd at several versions, replays
a path-traversal PoC (CVE-2021-41773) against each on an egress-less Docker network,
and stores whether the state oracle matched. This is the smallest proof of the whole
idea: a PoC that reproduces *before* a fix and stops *after* it.

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
