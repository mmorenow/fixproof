"""The verdict engine: what does running the PoC prove?

Questions the verdict engine answers:

  1. Is it real?            -> does the PoC reproduce at all? (the control)
  2. Is it a duplicate?     -> does an earlier report's fix also stop this PoC?
  3. Is it already fixed?   -> does it still reproduce on the latest version?
  4. Bypass or regression?  -> does it survive a fix, or come back after one?

Each verdict follows a deterministic rule based on the recorded replay outcomes.

To decide whether a new report N duplicates an earlier report O, we run N's PoC on
the version *before* O's fix and on the version *with* O's fix. Running N on the
pre-fix version is the control: it proves N's PoC actually works there. Only then
does its behaviour on the fixed version mean anything.
"""
from __future__ import annotations

from dataclasses import dataclass

from .runner import ReplayResult

# --- verdict labels ------------------------------------------------------------
# Fix-differential (N compared against one candidate O's fix):
DUPLICATE = "DUPLICATE"            # N stops working once O's fix is applied
BYPASS = "BYPASS"                  # N still works with O's fix -> a distinct bug
NOVEL = "NOVEL"                    # N reproduces but no candidate's fix covers it
# Reproduction / evidence:
NOT_REPRODUCED = "NOT_REPRODUCED"  # N never worked, even pre-fix -> no evidence
NEEDS_INFO = "NEEDS_INFO"          # the report lacks a field needed to build a replay
ABSTAIN = "ABSTAIN"               # a run errored or was inconsistent -> can't decide

# Every label the fix-differential / candidate path can emit.
TRIAGE_LABELS = frozenset({DUPLICATE, BYPASS, NOVEL, NOT_REPRODUCED, NEEDS_INFO, ABSTAIN})


@dataclass
class Verdict:
    label: str
    reason: str


def decide(pre_fix: ReplayResult, post_fix: ReplayResult) -> Verdict:
    """The fix-differential: given N run before and after a candidate's fix, decide
    whether that fix covers N (DUPLICATE) or not (BYPASS)."""
    if pre_fix.outcome == "error" or post_fix.outcome == "error":
        return Verdict(ABSTAIN, "a replay errored; cannot decide")

    if pre_fix.outcome != "pass":
        # The pre-fix replay must reproduce before the post-fix result can be used.
        return Verdict(NOT_REPRODUCED, "the new PoC did not reproduce on the pre-fix version")

    if post_fix.outcome == "fail":
        return Verdict(DUPLICATE, "the candidate's fix stops the new PoC")

    return Verdict(BYPASS, "the new PoC still works with the candidate's fix applied")


# Fix-verification (patch-on-top): is a proposed fix sufficient?
FIX_CONFIRMED = "FIX_CONFIRMED"    # the PoC stops working once the patch is applied
FIX_INCOMPLETE = "FIX_INCOMPLETE"  # the PoC still works after the patch -> not fixed


def verify_fix(unpatched: ReplayResult, patched: ReplayResult) -> Verdict:
    """Patch-on-top: run the PoC on the unpatched build (the control) and on the
    build with a candidate fix applied on top. This answers "does *this* patch
    actually stop the bug?" — including for unreleased or internal fixes that no
    public version carries yet, which is exactly what an outside platform cannot do.

    It is the fix-differential again, named for fix verification instead of dedup:
    the unpatched run must reproduce (else there is nothing to verify), and the
    patched run deciding fail vs. pass is FIX_CONFIRMED vs. FIX_INCOMPLETE."""
    if unpatched.outcome == "error" or patched.outcome == "error":
        return Verdict(ABSTAIN, "a replay errored; cannot verify the fix")
    if unpatched.outcome != "pass":
        return Verdict(NOT_REPRODUCED, "the PoC did not reproduce on the unpatched build; nothing to verify")
    if patched.outcome == "fail":
        return Verdict(FIX_CONFIRMED, "the patch stops the PoC")
    return Verdict(FIX_INCOMPLETE, "the PoC still works after the patch")


def decide_no_candidate(reproduces_on_latest: bool | None) -> Verdict:
    """When search proposes no candidate to compare against, the fix-differential
    cannot run. The honest outcome depends only on whether N reproduces on the
    latest version: if it does, it is a NOVEL finding worth a human's time; if it
    does not, there is nothing to act on; if we could not test, we abstain."""
    if reproduces_on_latest is None:
        return Verdict(ABSTAIN, "no candidate to compare against and latest could not be tested")
    if reproduces_on_latest:
        return Verdict(NOVEL, "no known candidate's fix covers this PoC, and it reproduces on the latest version")
    return Verdict(NOT_REPRODUCED, "no candidate to compare against, and the PoC does not reproduce on the latest version")


# --- scanning a version ladder -------------------------------------------------

# Status for "run this PoC across an ordered list of versions, oldest -> newest".
REAL_AT_LATEST = "REAL_AT_LATEST"        # still works on the newest version
ALREADY_FIXED = "ALREADY_FIXED"          # worked on an older version, fixed since
REGRESSION = "REGRESSION"                # worked, was fixed, then works again later
NEVER_REPRODUCED = "NEVER_REPRODUCED"    # never worked on any version tested

SCAN_LABELS = frozenset({REAL_AT_LATEST, ALREADY_FIXED, REGRESSION, NEVER_REPRODUCED})


@dataclass
class ScanResult:
    status: str
    fixed_in: str | None          # first version where it stopped working
    last_vulnerable: str | None   # last version where it still worked
    per_version: list[dict]
    regressed_in: str | None = None  # first version where it worked again after a fix


def scan_ladder(versions: list[str], results: list[ReplayResult]) -> ScanResult:
    """Given versions oldest->newest and their replay results, find the fix
    boundary, whether the bug still reproduces on the newest version, and whether
    a fix later regressed (the bug came back).

    'error' outcomes are carried into per_version for transparency but ignored when
    locating boundaries: an environment that failed to stand up is not evidence that
    a bug was fixed. Only an observed pass/fail transition moves a boundary.
    """
    per = [
        {"version": v, "outcome": r.outcome, "matched": r.matched}
        for v, r in zip(versions, results)
    ]

    # Work on the observed (non-error) outcomes, keeping each one's version.
    observed = [(v, r.outcome) for v, r in zip(versions, results) if r.outcome in ("pass", "fail")]
    passes = [v for v, o in observed if o == "pass"]
    if not passes:
        return ScanResult(NEVER_REPRODUCED, None, None, per)

    last_vulnerable = passes[-1]

    # The fix boundary is the first observed fail that comes after the first pass.
    fixed_in: str | None = None
    seen_pass = False
    for v, o in observed:
        if o == "pass":
            seen_pass = True
        elif o == "fail" and seen_pass:
            fixed_in = v
            break

    # A pass after the fix boundary indicates a regression.
    regressed_in: str | None = None
    if fixed_in is not None:
        after_fix = False
        for v, o in observed:
            if v == fixed_in:
                after_fix = True
                continue
            if after_fix and o == "pass":
                regressed_in = v
                break

    # Status is read off the newest *observed* outcome plus the regression flag.
    newest_observed = observed[-1][1]
    if regressed_in is not None and newest_observed == "pass":
        status = REGRESSION
    elif newest_observed == "pass":
        status = REAL_AT_LATEST
    else:
        status = ALREADY_FIXED
    return ScanResult(status, fixed_in, last_vulnerable, per, regressed_in)
