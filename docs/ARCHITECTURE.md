# FixProof: architecture

## 1. The problem

Security teams receive findings from bug bounty hunters, pentesters, their own engineers, customers and scanners. For every incoming report they have to answer four questions:

1. Is it real?
2. Is it a duplicate of something we already have?
3. Is it already fixed?
4. Is it a bypass of an earlier fix, or a regression?

The industry defines a duplicate by the fix: two reports are the same bug if one patch fixes both (Bugcrowd: "similar ≠ same"; Intigriti: "would the first fix have fixed the second?"; CNA rule 4.1.9: "independently fixable").

Deployed dedup tools don't test that. HackerOne, Intigriti and Bugcrowd compare text, embeddings and endpoint fingerprints. They never execute anything and never look at the fix. Tools that do reproduce bugs (Elastic's triage agent, HackerOne h1 Validation) don't deduplicate. All of them live inside closed platforms. Open-source maintainers, small PSIRTs and internal AppSec teams have nothing.

## 2. The idea

**Turn every finding with a PoC into a replayable test, and decide by running it.**

To check whether a new report N is the same bug as an earlier report O, run N's PoC on two versions of the app:

| N on the version **without** O's fix | N on the version **with** O's fix | Verdict |
|---|---|---|
| works | stops working | **DUPLICATE**: O's fix covers it |
| works | still works | **NEW** or **BYPASS** of O's fix |
| fails | fails | **NOT REPRODUCED**: a human checks it |

The same engine answers the other questions:

- **Is it real today?** Run N on the latest version.
- **Already fixed?** If N fails on latest, walk back through versions to find where it stopped working. That boundary points to the fix, and the fix points to the original report.
- **Regression?** A PoC that a fix blocked works again on a later version.
- **Original not fixed yet?** N stays a *possible duplicate* and is re-run automatically when O's fix lands.
- **Security regression testing.** Every stored PoC is re-run on each new release.

Running the PoC on the version *without* the fix is the control. It proves the PoC works, so if it then fails on the fixed version, the fix is what stopped it.

**Guiding principle: the LLM proposes, execution decides.** Models help read reports and draft PoC scripts. The verdict always comes from deterministic rules applied to execution results, never from a model.

## 3. Who it is for

- **Primary:** anyone who receives security findings without big-platform tooling.
  - Open-source maintainers getting reports through GitHub Private Vulnerability Reporting or email.
  - Small or internal PSIRTs and AppSec teams.
  - Companies with private apps. They can test against their own unreleased fixes, which no outsider can see.
- **Also:**
  - Pentest retests (fix verification).
  - Spotting the same bug arriving through different channels.
  - Regression testing of past findings.
- **Secondary:** hunters who want to check that their PoC works, and isn't already fixed, before submitting. Their PoC becomes a replay artifact the receiving team can run directly.

It is vendor-agnostic, self-hosted, and works with the user's own model keys or a local model.

## 4. Pipeline

```
                 ┌───────────────────────────────────────────┐
                 │ LLM gateway (LiteLLM): any provider/local │
                 └─────────────────────┬─────────────────────┘
                                       │ proposes only
 1. INTAKE           2. UNDERSTAND (LLM)          3. EXECUTE (deterministic)
 ─────────           ───────────────────          ──────────────────────────
 GitHub PVR    ┐     extract claim           ┐    get snapshots (versions)
 email         ├──▶  compile PoC → test      ├──▶ run in sandbox (K times)
 API / CLI     │     propose candidates      │    verdict rules + policy
 report file   ┘     (similar past reports)  ┘    guardrails → human review
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 │ FastAPI + PostgreSQL (pgvector) + job queue│
                 └───────────────────────────────────────────┘
                 4. LATER: re-run when a fix lands; regression runs per release
```

### Step 1: Intake
Adapters normalize every source into one `Report`: GitHub PVR webhook, email (IMAP/.eml), JSON from platforms, CLI/API upload, pentest reports (Markdown/PDF).

### Step 2: Understand (LLM proposes)
- **Claim extraction.** Report text becomes a typed record: product, tested version, vuln class, endpoint, parameter, auth context, PoC steps, and what the PoC is supposed to prove. When a required field is missing, the verdict is **NEEDS-INFO**. The system doesn't guess.
- **PoC compiler.** Turns the claim into a replay artifact plus a state oracle (see below). It is semi-automatic: an LLM draft, a template library per vuln class, then confirmation by running it on the vulnerable version or by a human.
- **Candidate proposer.** Cheap hybrid search over past reports: Postgres full-text plus pgvector embeddings plus an endpoint/parameter/CWE fingerprint. It only picks *which* earlier reports to test against. Similarity never decides.

### Step 3: Execute (execution decides)
- **Snapshot provider.** Gets the versions to test, cheapest first:
  1. official versioned images (e.g. `httpd:2.4.49`);
  2. build from git at `parent(fix)` and at `fix`;
  3. **patch-on-top**: vulnerable base plus the fix diff. This works even for fixes that haven't been released yet, including private internal fixes;
  4. bisection across versions to find `fixed_in` / `introduced_in`.

  A fix is treated as a *set* of commits, since many vulnerabilities need several patches.
- **Sandboxed runner.** Runs `artifact × snapshot × K` (K ≥ 3, majority vote).
  - Before judging a negative, it checks that the app booted and the feature exists, so "the environment broke" never reads as "it's fixed".
  - It stores the request/response diffs as evidence.
- **Verdict engine.** Fixed rules map the outcome matrix to DUPLICATE, BYPASS, REGRESSION, NEW, ALREADY-FIXED, NOT-REPRODUCED or ABSTAIN.
- **Policy layer.** Declarative presets encode each receiver's rules (Bugcrowd, HackerOne, CNA counting rules, or custom ones). For example: regressions are never closed as duplicates.

### Step 4: Later
- **Provisional re-run.** When O is accepted but unfixed, N waits as POSSIBLE-DUPLICATE. A job re-runs it when O's fix commit or release appears.
- **Regression ledger.** All stored artifacts are re-run on each new release.

## 5. Replay artifacts and oracles

**Formats:**
- **Nuclei templates** (YAML requests plus matchers), the default: reviewable, versionable, multi-step.
- **Python `httpx` scripts** (from a HAR/Burp export) for logic Nuclei can't express.
- **Playwright** for browser-side bugs.

**State oracles.** A test passes only if a real state change is observed, never just on an HTTP 200. Each environment is seeded with canary data:

| Class | The test passes if… |
|---|---|
| IDOR / BOLA | the attacker gets a canary resource owned by a victim user |
| Path traversal | a canary file outside the web root is read |
| Auth bypass | an anonymous request gets a resource that requires auth |
| SQLi | a canary row is read (read-only, never destructive) |
| XSS | the canary lands in an executable context (Playwright) |
| SSRF | an internal canary service receives a callback |

**Payload neutralization.** A reporter's payload is never run as-is. It is rewritten to a benign canary first.

## 6. Safety and guardrails

- **Sandbox.**
  - gVisor where available.
  - Otherwise hardened Docker: no internet egress, read-only filesystem, all capabilities dropped, non-root, CPU/memory/PID limits, timeouts.
  - Targets are only local containers, never real systems.
- **Reports are untrusted input.** A report can contain prompt injection. Countermeasures:
  - agents get minimal tools and no credentials;
  - agent output never acts directly; it goes through the orchestrator;
  - the project includes red-team tests with malicious reports.
- **The LLM never emits a verdict.** This guards against LLMs' documented tendency to over-accept invalid reports.
- **Duplicate graph integrity** (enforced in PostgreSQL):
  - no cycles in `duplicate_of`, via a recursive-CTE trigger;
  - exactly one open canonical report per cluster, via a partial unique index;
  - only legal state transitions;
  - an append-only audit log.
- **Human in the loop** for every close. Confidence and evidence are always shown.
- **Shareable rationale.** A redacted "why this is a duplicate" summary a team can send to a disputing hunter without leaking the original.

## 7. Tech stack

| Concern | Choice |
|---|---|
| API | FastAPI |
| Database, search, vectors | PostgreSQL + pgvector (+ full-text search) |
| Job queue (builds, runs, re-runs) | Procrastinate (Postgres-backed, no Redis) |
| Model access (bring your own key or local) | LiteLLM (any provider, Ollama/vLLM local) |
| Agents (typed LLM steps) | PydanticAI. LangGraph only if the agent flow becomes a real branching graph. |
| Replay | Nuclei, httpx, Playwright |
| Environments | Docker / Docker Compose, gVisor |
| Known-fix data | local OSV/GHSA mirror + git (`git tag --contains <fix>`) |

## 8. Data model (core)

```
reports(id, source, external_id, text, tested_version, fingerprint, filed_at, state)
claims(report_id, product, vuln_class, endpoint, parameter, method, auth_context)
replay_artifacts(id, report_id, kind, body, oracle, neutralized)
snapshots(id, product, ref {image|commit|patch_set}, fix_refs, built_at)
replay_runs(id, artifact_id, snapshot_id, attempt, outcome, evidence, duration_ms)
verdicts(report_id, label, original_id, confidence, evidence, policy, decided_by)
clusters(id, canonical_report_id)
edges(src, dst, type, state, policy_rule)        -- anti-cycle trigger
fixes(id, product, commits[], released_in)
events(...)                                      -- append-only audit log
```

## 9. Phases

| Phase | Goal | Done when |
|---|---|---|
| **0. Skeleton** | Repo, FastAPI + Postgres, hardened runner | One API call runs a Nuclei template against `httpd:2.4.49` and `2.4.50` and stores both results |
| **1. Execution core** | Oracles for 3 classes (path traversal, IDOR, auth bypass), version ladder, `fixed_in` bisection | The Apache demo (section 10) works end to end |
| **2. Verdicts** | Fix-differential, patch-on-top, verdict engine, policy presets, graph guardrails, human review | The tool returns typed verdicts with evidence. **This completes the core.** |
| **3. Intake + memory** | GitHub PVR + email intake, candidate search, provisional re-run, regression ledger | A report arriving by webhook gets a verdict automatically |
| **4. LLM layer + hardening** | Claim extraction, PoC compiler, BYO model, prompt-injection red-team | A plain-text report becomes a verified replay test |
| **5. Proof + release** | Evaluation on public cases, docs, demo video | Published numbers: verdict accuracy, abstention rate, false merges |

**Later:** browser bugs (Playwright), more vuln classes, a GitHub Action / CI mode, and a hunter mode.

## 10. Flagship demo

Apache httpd shipped an incomplete fix: CVE-2021-41773 was fixed in 2.4.50, and CVE-2021-42013 bypassed that fix until 2.4.51. Official images for 2.4.49, 2.4.50 and 2.4.51 exist.

| Report | 2.4.49 | 2.4.50 (O's fix) | 2.4.51 | Verdict |
|---|---|---|---|---|
| O: path traversal with `.%2e/` | works | fails | fails | real, `fixed_in = 2.4.50` |
| N: same bug with `%%32%65` | works | **still works** | fails | **BYPASS**, not a duplicate |

A text-similarity tool would merge O and N: same file, same CWE, almost identical wording. Execution separates them.

## 11. Evaluation (proves it works; not the product)

- **Bypass / incomplete-fix pairs with runnable environments:** Apache, Apache Shiro's chain of incomplete auth-bypass fixes, Struts, and Vulhub cases. NVD lists 848 "incomplete fix for CVE" entries.
- **Fix-coverage labels:** BountyBench, by crossing each system's patches with its exploits. CVE-Bench.
- **Retrieval and hard negatives:** public duplicate data from Mozilla Bugzilla, Chromium/Firefox (Atefi et al.) and disclosed HackerOne reports.
- **Metrics:** verdict accuracy, abstention rate and precision when it doesn't abstain, false merges on hard negatives, PoC compile success rate, cost and latency per report.

## 12. Prior art and positioning

- **Platform dedup** (HackerOne, Intigriti, Bugcrowd): similarity only, no execution, closed.
- **Reproduction agents** (Elastic, Casco, h1 Validation): reproduce, don't dedupe, closed.
- **Retest tools** (Bugcrowd's AI-generated Nuclei retests, Escape's regression agent): retest the same finding, don't decide duplicates.
- **Kritolith** (open source, pre-alpha): the closest. It replays against the vulnerable commit and HEAD, but not against another report's fix.
- **Patent note:** US11301367B2 claims deriving regression tests from PoCs in a SaaS platform. This project is self-hosted open source and its core (fix-differential duplicate decisions) is different. Review the claims before offering a managed service.

Background research with sources: `docs/research/`.
