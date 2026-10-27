# FixProof — blind validation run (2026-10-27)

A test of whether FixProof reaches the *correct* verdict on real, already-patched
vulnerabilities — without being told the answer.

## The setup

For each case, the operator knows the ground truth from the vendor advisory (which
version shipped the fix). FixProof does **not**: its verdict comes only from running
the PoC against each version in a sandbox and reading a state oracle. It is handed a
version ladder with the fix boundary **hidden**, and must find `fixed_in` itself by
execution. We then compare its blind answer to the advisory.

This is the whole thesis under test: a tool that decides by running the exploit,
not by reading text, should land on the boundary the vendor actually shipped.

## Results

| Software | CVE | Vuln class | Ladder (hidden boundary) | Ground truth | FixProof (blind) | Match |
|---|---|---|---|---|---|---|
| Apache httpd | CVE-2021-41773 | URL path traversal | 2.4.49 → 2.4.50 → 2.4.51 | fixed in 2.4.50 | `ALREADY_FIXED`, `fixed_in=2.4.50` | ✅ |
| Apache httpd | CVE-2021-42013 | bypass of the 41773 fix | run before/after the 2.4.50 fix | a distinct bug (fixed 2.4.51) | `BYPASS` (survives 2.4.50) | ✅ |
| Grafana | CVE-2021-43798 | plugin path traversal | 8.3.0 → 8.3.1 | fixed in 8.3.1 | `ALREADY_FIXED`, `fixed_in=8.3.1` | ✅ |
| MLflow | CVE-2023-1177 | model-registry LFI | 2.1.1 → 2.2.1 | fixed in 2.2.1 | `ALREADY_FIXED`, `fixed_in=2.2.1` | ✅ |
| Apache Flink | CVE-2020-17519 | JobManager REST traversal | 1.11.2 → 1.11.3 | fixed in 1.11.3 | `ALREADY_FIXED`, `fixed_in=1.11.3` | ✅ |
| vulnapp (internal) | — (private fix) | path traversal | 1.0.0 + an unreleased patch | the patch closes it | `FIX_CONFIRMED` | ✅ |

Six for six. In every case the oracle is a real state change (the response body is
the actual `/etc/passwd`, or the planted canary), never just an HTTP 200 — so a
patched server that still answers 200 with an error page is correctly read as fixed.

### What each row shows

- **httpd 41773 / 42013** — the hard case for text similarity: two reports that read
  the same file and look almost identical, where one *bypasses* the other's fix.
  Execution separates them; a similarity deduper would merge them.
- **Grafana, MLflow, Flink** — three unrelated products, to show the engine is not
  tuned to one. Flink in particular was added *after* the engine was built: only a
  target spec and a PoC template, no engine changes.
- **vulnapp** — the case no outside platform can serve: a private app with no CVE
  and no public image, fixed only by an unreleased patch. FixProof builds it, applies
  the patch on top, and confirms the fix by execution.

## Environment note (and a finding)

The run was on an **arm64** host (Apple Silicon). Three of the targets are arm64
images; Apache Flink 1.11.x ships **amd64 only**, so FixProof runs it under Docker's
emulation (`--platform linux/amd64`).

Bringing Flink up surfaced a real interaction worth recording: the sandbox drops
**all** Linux capabilities, including `CAP_DAC_OVERRIDE` and `CAP_SETUID`. Flink's
image starts as root and its entrypoint switches to the `flink` user via `gosu` —
which needs `CAP_SETUID` — and rewrites its config — which, for root, needs
`CAP_DAC_OVERRIDE`. Under the sandbox both are denied, so the container exited with
`failed switching to "flink": operation not permitted`.

The fix was **not** to loosen the sandbox but to run the container directly as the
`flink` user, so no privileged user switch is needed (and the process is non-root
throughout). This is exactly the kind of friction a locked-down runner should
create, and the right resolution keeps the lockdown intact.

## Reproduce

```bash
docker compose up -d
uv run pytest -q            # 38 tests; test_smoke.py + test_patch_on_top.py cover every row above
```

Or hit the API directly (see fixproof/README.md) with `/scan` for the ladders and
`/verify-fix` for patch-on-top.

## Honest limitations

- This validates **verdict correctness on true positives** (known real bugs with
  known fixes) plus one true bypass. It is not yet a measure of the **false-merge
  rate on hard negatives** (distinct bugs that look alike) — that needs a labelled
  negative set and is future work (see `docs/ARCHITECTURE.md` §11).
- The PoCs here are hand-written Nuclei templates, as the tool assumes today; the
  LLM-assisted PoC compiler (Phase 4) is not built.
- All six are file-read / path-traversal class, FixProof's strongest oracle so far.
  Other classes (IDOR, auth bypass, SQLi, SSRF) are designed but not yet wired.
