"""Unit tests for the verdict engine. Pure logic over ReplayResult values — no
Docker, no Postgres, no network. Run with: uv run pytest tests/test_verdict.py
"""
from __future__ import annotations

from app import verdict
from app.runner import ReplayResult


def _r(outcome: str, matched: bool | None = None) -> ReplayResult:
    """A ReplayResult with just the fields the verdict engine reads."""
    if matched is None:
        matched = outcome == "pass"
    return ReplayResult(outcome=outcome, matched=matched, evidence={}, duration_ms=0)


# --- decide(): the fix-differential -------------------------------------------

def test_duplicate_when_fix_stops_the_poc():
    # Works before the fix, stops after it -> the fix covers it -> DUPLICATE.
    assert verdict.decide(_r("pass"), _r("fail")).label == verdict.DUPLICATE


def test_bypass_when_poc_survives_the_fix():
    # Works before AND after the fix -> the fix does not cover it -> BYPASS.
    assert verdict.decide(_r("pass"), _r("pass")).label == verdict.BYPASS


def test_not_reproduced_when_control_fails():
    # The control (pre-fix) did not reproduce, so nothing downstream is trustworthy.
    assert verdict.decide(_r("fail"), _r("fail")).label == verdict.NOT_REPRODUCED
    # Even if the post-fix run "passes", a failed control means no evidence.
    assert verdict.decide(_r("fail"), _r("pass")).label == verdict.NOT_REPRODUCED


def test_abstain_on_error():
    assert verdict.decide(_r("error"), _r("fail")).label == verdict.ABSTAIN
    assert verdict.decide(_r("pass"), _r("error")).label == verdict.ABSTAIN


# --- decide_no_candidate(): nothing to compare against ------------------------

def test_no_candidate_reproduces_on_latest_is_novel():
    assert verdict.decide_no_candidate(True).label == verdict.NOVEL


def test_no_candidate_does_not_reproduce_is_not_reproduced():
    assert verdict.decide_no_candidate(False).label == verdict.NOT_REPRODUCED


def test_no_candidate_untested_abstains():
    assert verdict.decide_no_candidate(None).label == verdict.ABSTAIN


# --- verify_fix(): patch-on-top -----------------------------------------------

def test_fix_confirmed_when_patch_stops_poc():
    assert verdict.verify_fix(_r("pass"), _r("fail")).label == verdict.FIX_CONFIRMED


def test_fix_incomplete_when_poc_survives_patch():
    assert verdict.verify_fix(_r("pass"), _r("pass")).label == verdict.FIX_INCOMPLETE


def test_cannot_verify_fix_without_reproduction():
    assert verdict.verify_fix(_r("fail"), _r("fail")).label == verdict.NOT_REPRODUCED


def test_verify_fix_abstains_on_error():
    assert verdict.verify_fix(_r("pass"), _r("error")).label == verdict.ABSTAIN


# --- scan_ladder(): walking a version ladder ----------------------------------

def test_scan_real_at_latest():
    sr = verdict.scan_ladder(["1", "2", "3"], [_r("pass"), _r("pass"), _r("pass")])
    assert sr.status == verdict.REAL_AT_LATEST
    assert sr.last_vulnerable == "3"
    assert sr.fixed_in is None and sr.regressed_in is None


def test_scan_already_fixed_finds_boundary():
    sr = verdict.scan_ladder(["1", "2", "3"], [_r("pass"), _r("fail"), _r("fail")])
    assert sr.status == verdict.ALREADY_FIXED
    assert sr.last_vulnerable == "1" and sr.fixed_in == "2"
    assert sr.regressed_in is None


def test_scan_never_reproduced():
    sr = verdict.scan_ladder(["1", "2"], [_r("fail"), _r("fail")])
    assert sr.status == verdict.NEVER_REPRODUCED
    assert sr.fixed_in is None and sr.last_vulnerable is None


def test_scan_detects_regression():
    # pass -> fail -> pass: fixed in "2", then it came back in "3".
    sr = verdict.scan_ladder(["1", "2", "3"], [_r("pass"), _r("fail"), _r("pass")])
    assert sr.status == verdict.REGRESSION
    assert sr.fixed_in == "2" and sr.regressed_in == "3"
    assert sr.last_vulnerable == "3"


def test_scan_regression_then_refixed_reports_latest_state():
    # pass -> fail -> pass -> fail: it regressed, but the newest version is fixed,
    # so the status reflects the latest state while regressed_in still records it.
    sr = verdict.scan_ladder(
        ["1", "2", "3", "4"], [_r("pass"), _r("fail"), _r("pass"), _r("fail")]
    )
    assert sr.status == verdict.ALREADY_FIXED
    assert sr.fixed_in == "2" and sr.regressed_in == "3"


def test_scan_ignores_errors_when_locating_boundary():
    # An errored run (environment broke) must not read as "fixed here".
    sr = verdict.scan_ladder(["1", "2", "3"], [_r("pass"), _r("error"), _r("fail")])
    assert sr.status == verdict.ALREADY_FIXED
    assert sr.fixed_in == "3" and sr.last_vulnerable == "1"
