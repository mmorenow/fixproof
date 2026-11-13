# FixProof — usage

Every endpoint, with copy-paste examples. For the what and why, start at the
[project README](../README.md).

FixProof stands up a target at several versions, replays a PoC against each on an
egress-less Docker network, and decides — by running the PoC, not by comparing text
— whether a new report is a duplicate, a bypass, a regression, already fixed, or
simply not reproducible. It can also verify an **unreleased fix** by applying the
patch on top of a built image (patch-on-top).

> In 2026, bug-bounty programs (Google OSS VRP, curl, CycloneDX) buckled under
> AI-generated reports that read well but run nothing. FixProof's answer: a report
> with no reproducible evidence gets `NOT_REPRODUCED` and a request for a PoC, never
> a verdict. The LLM proposes; execution decides.

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

## Scan a version ladder ("is it already fixed? did it come back?")

```bash
curl -s -X POST localhost:8099/scan -H 'content-type: application/json' \
  -d '{"template":"cve-2021-41773","versions":["2.4.49","2.4.50","2.4.51"]}'
# -> status ALREADY_FIXED, last_vulnerable 2.4.49, fixed_in 2.4.50
```

The scan also detects **regressions** (`pass → fail → pass` across the ladder: a fix
that was undone in a later version) and reports `regressed_in`.

## Verify an unreleased fix (patch-on-top)

The case no outside platform can serve: a private app with **no CVE and no public
image**, whose fix ships in no released version — only the team's own patch. FixProof
builds the vulnerable app, applies the fix diff *on top* of that image, and re-runs
the PoC. If the PoC stops, the fix is confirmed — proven by execution, not by reading
the diff.

```bash
curl -s -X POST localhost:8099/verify-fix -H 'content-type: application/json' -d '{
  "product":"vulnapp","version":"1.0.0",
  "template":"vulnapp-path-traversal","fix":"path-traversal"}'
# -> verdict FIX_CONFIRMED: the PoC reads the canary before the patch, and the
#    patch (targets/vulnapp/fixes/path-traversal.patch) stops it.
```

A patch that does *not* stop the PoC returns `FIX_INCOMPLETE`; a PoC that never
reproduced on the unpatched build returns `NOT_REPRODUCED` (nothing to verify).

## Verdicts and policies

The verdict engine (`app/verdict.py`) emits a typed label — `DUPLICATE`, `BYPASS`,
`NOVEL`, `REGRESSION`, `NOT_REPRODUCED`, `NEEDS_INFO`, `ABSTAIN` — purely from
execution outcomes. The policy layer (`app/policy.py`) turns that into an action
under the receiver's counting rules (`GET /policies` lists the presets):

| Preset | Behaviour |
|---|---|
| `default` | auto-close confident duplicates, auto-open distinct bugs, request evidence when nothing reproduces |
| `conservative` | change nothing automatically; every close and new issue is human-confirmed |
| `cna` | CVE counting rules: independently fixable bugs (bypass/regression) are always counted separately |

Two safety invariants hold under **every** preset: a `BYPASS`/`REGRESSION` is never
closed as a duplicate, and a report with no reproducible evidence never triggers a
state change — the gate against AI-generated noise.

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
uv run pytest tests/test_verdict.py tests/test_policy.py tests/test_api.py   # pure: no Docker, under a second
uv run pytest -s                                                             # everything, including real-CVE replays (Docker + Postgres)
```

The pure tests cover the verdict rules, the policy invariants and the API's input
handling. The Docker tests replay each PoC against the real product versions and
assert the outcome the vendor advisory says it should have.

## Layout

```
app/
  main.py      FastAPI endpoints: /triage, /triage/auto, /scan, /verify-fix, /search, /policies, /replays
  runner.py    starts a target + nuclei container on the isolated network; builds/pulls/patches images
  verdict.py   the verdict engine: outcomes -> DUPLICATE/BYPASS/NOVEL/REGRESSION/NOT_REPRODUCED/... and verify_fix
  policy.py    counting-rule presets: a verdict -> an action, with safety invariants
  search.py    lexical candidate proposer (full-text + trigram) over past reports
  catalog.py   reports we can replay (template + fix boundary)
  ingest.py    pulls real CVE text from OSV
  db.py        psycopg3 helpers
  schema.sql   reports, replay_runs, verdicts, ...
  config.py    env-driven settings
replays/       PoCs as Nuclei templates (the state oracles)
targets/
  httpd-cve-2021-41773/httpd.conf   deliberately vulnerable Apache config
  mlflow/                           build-local target (no official image)
  vulnapp/                          the patch-on-top demo app + fixes/*.patch (unreleased fix)
tests/         test_verdict.py, test_policy.py, test_api.py (pure); test_smoke.py, test_patch_on_top.py (Docker)
```

## Isolation (the PoC is the untrusted input)

FixProof runs reporter-supplied PoCs, so every container the engine spawns — the
target, the nuclei runner that interprets the PoC, and the readiness probe — starts
locked down (`app/runner.py:_hardening_flags`):

- **No egress.** They share an `--internal` Docker network with no route to the
  host or the internet. A PoC can reach the target and nothing else.
- **All capabilities dropped.** `--cap-drop ALL`; a target adds back only what it
  needs (httpd re-gains `NET_BIND_SERVICE` to bind port 80; Grafana and MLflow,
  on high ports, add back nothing). A hardened container shows `CapEff: 0`.
- **No privilege escalation.** `--security-opt no-new-privileges` everywhere.
- **Bounded resources.** `--pids-limit` and `--memory` so a PoC cannot fork-bomb
  or balloon the host (`FIXPROOF_PIDS_LIMIT`, `FIXPROOF_MEMORY_LIMIT`).
- **gVisor, optional.** Set `FIXPROOF_RUNTIME=runsc` to run every container under
  gVisor where it is installed. Left unset it uses Docker's default runtime, so
  the sandbox works everywhere and gVisor is a drop-in upgrade, not a dependency.

### The API itself

- **Localhost only, no authentication.** The API drives the Docker daemon, which is
  root-equivalent on the host. Run it on `127.0.0.1` (uvicorn's default) and do not
  expose it.
- **Request names are not paths.** Template, fix and product names and version
  strings are restricted to a safe alphabet and resolved inside `replays/` and
  `targets/` only (`tests/test_api.py`), so a request cannot read another file or
  pass an option to the docker CLI.
- **Fail closed.** An unknown policy name is rejected, never replaced by the
  default, and a hung container becomes an `error` outcome (the verdict engine
  abstains) rather than a guess.

## Notes

- Host port 55432 avoids a clash with a local Postgres on 5432. Override with
  `FIXPROOF_DATABASE_URL`.
