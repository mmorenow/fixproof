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
