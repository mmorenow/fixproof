<div align="center">

# FixProof

**Triage vulnerability reports by execution, not by similarity.**

[![ci](https://github.com/mmorenow/fixproof/actions/workflows/ci.yml/badge.svg)](https://github.com/mmorenow/fixproof/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%2B-3776ab)
![sandbox](https://img.shields.io/badge/sandbox-no%20egress%20%C2%B7%20cap--drop%20ALL-0a0a0a)
![license](https://img.shields.io/badge/license-MIT-2ea44f)

<img src="docs/assets/demo.gif" alt="FixProof replays a PoC before and after another report's fix and returns BYPASS" width="860">

</div>

Two reports. Both read `/etc/passwd` through an encoded `../` in Apache httpd. Same
file, same CWE, nearly the same wording. A similarity-based deduplicator merges them
and closes the second one as a duplicate.

The second one is CVE-2021-42013: a bypass of the first one's fix, exploited in the
wild. FixProof keeps it open, because it ran the PoC and watched it survive the patch.

## The idea

The industry already defines a duplicate by the fix, not by the text: two reports are
the same bug **if one fix fixes both** (Bugcrowd's "similar ≠ same", Intigriti's "would
the first fix have fixed the second?", CNA rule 4.1.9 "independently fixable").
Deployed dedup tooling compares text, embeddings and endpoint fingerprints. None of it
tests the fix.

FixProof tests the fix. It replays the new report's PoC on the version right before
the earlier report's fix and on the version right after it, inside a locked-down
sandbox, and reads the result:

```text
  the new report's PoC...
  before the fix        after the fix         verdict
  ──────────────────────────────────────────────────────────
  reproduces       →    stopped               DUPLICATE
  reproduces       →    still works           BYPASS
  never worked                                NOT_REPRODUCED
  a run errored                               ABSTAIN
```

The run before the fix is the control: it proves the PoC works at all. Only then does
its behavior after the fix mean anything. A report whose PoC never reproduces gets a
request for evidence, not a verdict, which is the whole defense against well-written
reports that run nothing.

> Search proposes. Execution decides.

## See it decide

Real output, real CVEs. Is CVE-2021-42013 a duplicate of CVE-2021-41773, which was
fixed in httpd 2.4.50?

```console
$ curl -s localhost:8099/triage --json @examples/triage-bypass.json \
    | jq '{verdict, reason, action: .disposition.action}'
{
  "verdict": "BYPASS",
  "reason": "the new PoC still works with the candidate's fix applied",
  "action": "KEEP_OPEN"
}
```

It survived the patch. So where was it actually fixed?

```console
$ curl -s localhost:8099/scan --json @examples/scan-ladder.json \
    | jq -c '{status, last_vulnerable, fixed_in}'
{"status":"ALREADY_FIXED","last_vulnerable":"2.4.50","fixed_in":"2.4.51"}
```

And a private app with no CVE and no public image, fixed only by a patch nobody has
released yet. Does the patch work?

```console
$ curl -s localhost:8099/verify-fix --json @examples/verify-fix.json | jq -c '{verdict, reason}'
{"verdict":"FIX_CONFIRMED","reason":"the patch stops the PoC"}
```

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

## Validated on real CVEs

Each row is a real product at real versions, stood up in the sandbox. FixProof is
given the version ladder, not the answer, and has to find the boundary by execution.
The result is then compared with the vendor advisory.

| Product | CVE | Class | Advisory says | FixProof found |
|---|---|---|---|---|
| Apache httpd | CVE-2021-41773 | URL path traversal | fixed in 2.4.50 | `ALREADY_FIXED`, `fixed_in=2.4.50` |
| Apache httpd | CVE-2021-42013 | bypass of that fix | distinct bug, fixed in 2.4.51 | `BYPASS` at 2.4.50, `fixed_in=2.4.51` |
| Grafana | CVE-2021-43798 | plugin path traversal | fixed in 8.3.1 | `ALREADY_FIXED`, `fixed_in=8.3.1` |
| MLflow | CVE-2023-1177 | model-registry file read | fixed in 2.2.1 | `ALREADY_FIXED`, `fixed_in=2.2.1` |
| Apache Flink | CVE-2020-17519 | REST path traversal | fixed in 1.11.3 | `ALREADY_FIXED`, `fixed_in=1.11.3` |
| private app | none (unreleased patch) | path traversal | the patch closes it | `FIX_CONFIRMED` |

Every oracle is a state change, never a status code: the PoC passes only if the
response body is the real `/etc/passwd` or a canary planted outside the web root. A
patched server that still answers `200` reads as fixed. The full write-up, including
what this does *not* prove yet, is in [`docs/VALIDATION.md`](docs/VALIDATION.md).

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

No engine changes. One target spec and one PoC template:

```python
# fixproof/app/targets.py
"grafana": TargetSpec(image_repo="grafana/grafana", port=3000),
```

```yaml
# fixproof/replays/cve-2021-43798.yaml  (a Nuclei template; the matcher is the oracle)
matchers:
  - type: regex
    part: body
    regex: ["root:.*:0:0:"]
```

Products without an official image are built from a Dockerfile at the requested
version (MLflow), and private apps are built from source with the fix applied as a
diff on top (`targets/vulnapp`).

## Limits

Stated plainly, because a triage tool that overclaims is worse than none.

- **Release-level differential.** `/triage` compares two released versions, so
  `DUPLICATE` means "something that shipped between them stops this PoC". When a
  release bundles several fixes, that is weaker than "the same fix". Patch-on-top
  isolates a single diff, but today it is wired to `/verify-fix` only.
- **`BYPASS` means "not covered by the candidate's fix".** That is a true bypass or an
  unrelated bug the search proposed by mistake. Either way it stays open; telling the
  two apart still takes a human.
- **One run per version.** A negative is "the oracle did not match", once. Repeated
  runs with a majority vote are designed, not built.
- **One vulnerability class.** Every PoC here is a file read. IDOR, auth bypass, SQLi
  and SSRF oracles are designed in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), not
  wired.
- **PoCs are hand-written Nuclei templates.** The step that turns a prose report into
  a replayable PoC is the next phase, along with intake from GitHub private
  vulnerability reports and email.

## Who it is for

Teams that receive security findings without big-platform tooling: open-source
maintainers, small PSIRTs, internal AppSec teams, and pentesters running retests.
Self-hosted and vendor-agnostic.

## Repo layout

```text
fixproof/               the tool: engine, API, target specs, PoC templates, tests
docs/ARCHITECTURE.md    the full pipeline, data model and roadmap
docs/VALIDATION.md      the validation run against vendor advisories
docs/research/          background: industry practice, academic work, practitioner pain
```

## License

[MIT](LICENSE)
