"""Phase 0 smoke test. Requires Docker and the Postgres container to be up
(`docker compose up -d`). Runs the real replay against three Apache versions and
asserts the known CVE-2021-41773 outcome: vulnerable in 2.4.49, fixed in 2.4.50+.

Run with: uv run pytest -s
"""
from __future__ import annotations

from app import config, verdict
from app.runner import run_replay

T41773 = config.REPLAYS_DIR / "cve-2021-41773.yaml"
T42013 = config.REPLAYS_DIR / "cve-2021-42013.yaml"


def test_apache_path_traversal_fix_boundary():
    assert T41773.exists()

    v49 = run_replay("httpd", "2.4.49", T41773)
    v50 = run_replay("httpd", "2.4.50", T41773)

    # The PoC reproduces before the fix and stops after it. This boundary is the
    # whole thesis in miniature: run a PoC against the version without a fix and
    # the version with it, and let the result decide.
    assert v49.outcome == "pass" and v49.matched is True, v49.evidence
    assert v50.outcome == "fail" and v50.matched is False, v50.evidence


def test_bypass_is_not_a_duplicate():
    # CVE-2021-42013 bypasses the 2.4.50 fix, so running it before and after that
    # fix yields BYPASS, not DUPLICATE — even though it reads the same file as
    # CVE-2021-41773 and looks almost identical in text.
    pre = run_replay("httpd", "2.4.49", T42013)
    post = run_replay("httpd", "2.4.50", T42013)
    assert verdict.decide(pre, post).label == verdict.BYPASS, (pre.evidence, post.evidence)


def test_true_duplicate_is_a_duplicate():
    # Re-submitting CVE-2021-41773 against itself: its fix stops it -> DUPLICATE.
    pre = run_replay("httpd", "2.4.49", T41773)
    post = run_replay("httpd", "2.4.50", T41773)
    assert verdict.decide(pre, post).label == verdict.DUPLICATE, (pre.evidence, post.evidence)
