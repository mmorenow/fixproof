"""Phase 0 smoke test. Requires Docker and the Postgres container to be up
(`docker compose up -d`). Runs the real replay against three Apache versions and
asserts the known CVE-2021-41773 outcome: vulnerable in 2.4.49, fixed in 2.4.50+.

Run with: uv run pytest -s
"""
from __future__ import annotations

from app import config
from app.runner import run_replay

TEMPLATE = config.REPLAYS_DIR / "cve-2021-41773.yaml"


def test_apache_path_traversal_fix_boundary():
    assert TEMPLATE.exists()

    v49 = run_replay("httpd", "2.4.49", TEMPLATE)
    v50 = run_replay("httpd", "2.4.50", TEMPLATE)

    # The PoC reproduces before the fix and stops after it. This boundary is the
    # whole thesis in miniature: run a PoC against the version without a fix and
    # the version with it, and let the result decide.
    assert v49.outcome == "pass" and v49.matched is True, v49.evidence
    assert v50.outcome == "fail" and v50.matched is False, v50.evidence
