<div align="center">

# FixProof

**Triage vulnerability reports by execution, not by similarity.**

[![ci](https://github.com/mmorenow/fixproof/actions/workflows/ci.yml/badge.svg)](https://github.com/mmorenow/fixproof/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%2B-3776ab)
![sandbox](https://img.shields.io/badge/sandbox-no%20egress%20%C2%B7%20cap--drop%20ALL-0a0a0a)
![license](https://img.shields.io/badge/license-MIT-2ea44f)

</div>

FixProof compares a report's replay results before and after a fix. The
pre-fix run is the control. FixProof requests a working proof of concept when
the report does not reproduce and abstains when a run errors.

## What it answers

| Question | Endpoint | How | Verdicts |
|---|---|---|---|
| Is this a duplicate of that report? | `POST /triage` | replay the PoC before and after the candidate's fix | `DUPLICATE` `BYPASS` `NOT_REPRODUCED` `ABSTAIN` |
| Which earlier report should I compare against? | `POST /search`, `POST /triage/auto` | full-text + trigram ranking over past reports (real CVE text from OSV), then the replay above | same, plus the ranked candidates |
| Is it already fixed, and where? Did it come back? | `POST /scan` | walk a version ladder, find the fix boundary | `REAL_AT_LATEST` `ALREADY_FIXED` `REGRESSION` `NEVER_REPRODUCED` |
| Does this unreleased patch actually stop it? | `POST /verify-fix` | build the app, apply the diff on top, replay | `FIX_CONFIRMED` `FIX_INCOMPLETE` |

A verdict says what the execution means. What to *do* about it is a separate,
declarative policy (`default`, `conservative`, `cna`), with two invariants no preset
can override: a bypass or regression is never closed as a duplicate, and a report with
no reproducible evidence never changes state on its own.

## Threat model: the PoC is hostile input

FixProof executes proof-of-concept code written by strangers. Every container it
spawns (the target, the Nuclei runner that interprets the PoC, the readiness probe)
starts from the same hardened baseline:

| Threat | Control |
|---|---|
| PoC phones home or pivots to the network | `--internal` Docker network: no egress, the PoC reaches the target and nothing else |
| Container escape through a privileged operation | `--cap-drop ALL`; a target adds back only what it needs (httpd gets `NET_BIND_SERVICE`, the rest get nothing) |
| Privilege escalation inside the container | `--security-opt no-new-privileges` |
| Fork bomb, memory balloon | `--pids-limit` and `--memory` on every container |
| A hung PoC holds the host | per-run timeouts; a hung container is removed and the run counts as an error, so the engine abstains |
| Malicious request to the API itself | template, fix and product names and versions are restricted to a safe alphabet and resolved inside their own directories; unknown policies are rejected, never defaulted |
| Stronger isolation needed | `FIXPROOF_RUNTIME=runsc` runs every container under gVisor where it is installed |

The lockdown is not loosened to make a target fit. Flink's image switches users with
`gosu`, which needs a capability the sandbox drops, so FixProof runs it directly as
the unprivileged `flink` user instead.

The API has no authentication and drives the Docker daemon. It is built to listen on
localhost.

## Quick start

Requires Docker and [uv](https://docs.astral.sh/uv/).

```bash
cd fixproof
docker compose up -d                        # Postgres
uv sync
uv run uvicorn app.main:app --port 8099
```

Then, from `fixproof/` in another shell, run any request in
[`examples/`](fixproof/examples):

```bash
curl -s localhost:8099/triage --json @examples/triage-bypass.json      # BYPASS
curl -s localhost:8099/triage --json @examples/triage-duplicate.json   # DUPLICATE
curl -s localhost:8099/scan --json @examples/scan-ladder.json          # fixed_in 2.4.51
curl -s localhost:8099/verify-fix --json @examples/verify-fix.json     # FIX_CONFIRMED
```

```bash
uv run pytest tests/test_verdict.py tests/test_policy.py tests/test_api.py   # pure logic, under a second
uv run pytest                                                                # plus the real-CVE replays
```

Every endpoint with examples: [`fixproof/README.md`](fixproof/README.md).

## Adding a product

Add a target spec in [`fixproof/app/targets.py`](fixproof/app/targets.py) and a
Nuclei template in [`fixproof/replays/`](fixproof/replays/). Targets can use an
existing container image or build one from a local Dockerfile.

## Limits

- `/triage` compares release versions. If a release bundles several changes,
  the result shows whether the release stops the PoC. Use `/verify-fix` to test
  a specific patch.
- A `BYPASS` verdict means the PoC still reproduces with the candidate's fix in
  place. Review the evidence to determine how the reports are related.
- Each replay runs once per version. The bundled templates cover file reads.
- Replay requires an existing Nuclei template.

## Repo layout

```text
fixproof/               the tool: engine, API, target specs, PoC templates, tests
```

## License

[MIT](LICENSE)
