"""The verdict rules: does the candidate's fix cover the new report?

This is the heart of FixProof. To decide whether a new report N is a duplicate of
an earlier report O, we don't compare text. We run N's PoC on the version *before*
O's fix and on the version *with* O's fix, and read the outcome.

Running N on the pre-fix version is the control: it proves N's PoC actually works
there. Only then does its behavior on the fixed version mean anything.
"""
from __future__ import annotations

from dataclasses import dataclass

from .runner import ReplayResult

# Verdict labels (a subset of docs/ARCHITECTURE.md; the full engine is Phase 2).
DUPLICATE = "DUPLICATE"            # N stops working once O's fix is applied
BYPASS = "BYPASS"                  # N still works with O's fix -> not the same bug
NOT_REPRODUCED = "NOT_REPRODUCED"  # N never worked, even pre-fix -> human
ABSTAIN = "ABSTAIN"               # a run errored -> can't decide


@dataclass
class Verdict:
    label: str
    reason: str


def decide(pre_fix: ReplayResult, post_fix: ReplayResult) -> Verdict:
    if pre_fix.outcome == "error" or post_fix.outcome == "error":
        return Verdict(ABSTAIN, "a replay errored; cannot decide")

    if pre_fix.outcome != "pass":
        # The PoC didn't even reproduce on the vulnerable version, so the control
        # failed and nothing downstream can be trusted.
        return Verdict(NOT_REPRODUCED, "the new PoC did not reproduce on the pre-fix version")

    if post_fix.outcome == "fail":
        return Verdict(DUPLICATE, "the candidate's fix stops the new PoC")

    return Verdict(BYPASS, "the new PoC still works with the candidate's fix applied")


# --- scanning a version ladder -------------------------------------------------

# Status for "run this PoC across an ordered list of versions".
REAL_AT_LATEST = "REAL_AT_LATEST"        # still works on the newest version
ALREADY_FIXED = "ALREADY_FIXED"          # worked on an older version, fixed since
NEVER_REPRODUCED = "NEVER_REPRODUCED"    # never worked on any version tested


@dataclass
class ScanResult:
    status: str
    fixed_in: str | None       # first version where it stopped working
    last_vulnerable: str | None  # last version where it still worked
    per_version: list[dict]


def scan_ladder(versions: list[str], results: list[ReplayResult]) -> ScanResult:
    """Given versions oldest->newest and their replay results, find the fix
    boundary and whether the bug still reproduces on the newest version."""
    per = [
        {"version": v, "outcome": r.outcome, "matched": r.matched}
        for v, r in zip(versions, results)
    ]
    passes = [v for v, r in zip(versions, results) if r.outcome == "pass"]
    if not passes:
        return ScanResult(NEVER_REPRODUCED, None, None, per)

    last_vulnerable = passes[-1]
    # The fix boundary is the first version after the last vulnerable one that fails.
    fixed_in = None
    seen_last = False
    for v, r in zip(versions, results):
        if v == last_vulnerable:
            seen_last = True
            continue
        if seen_last and r.outcome == "fail":
            fixed_in = v
            break

    newest_outcome = results[-1].outcome
    status = REAL_AT_LATEST if newest_outcome == "pass" else ALREADY_FIXED
    return ScanResult(status, fixed_in, last_vulnerable, per)
