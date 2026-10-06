"""Phase 0 smoke test. Requires Docker and the Postgres container to be up
(`docker compose up -d`). Runs the real replay against three Apache versions and
asserts the known CVE-2021-41773 outcome: vulnerable in 2.4.49, fixed in 2.4.50+.

Run with: uv run pytest -s
"""
from __future__ import annotations

import pytest

from app import config, db, search, verdict
from app.runner import run_replay

T41773 = config.REPLAYS_DIR / "cve-2021-41773.yaml"
T42013 = config.REPLAYS_DIR / "cve-2021-42013.yaml"


@pytest.fixture(scope="module", autouse=True)
def _schema():
    db.init_schema()


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


def test_search_ranks_related_report_first():
    # Insert two unrelated reports directly (no network) and confirm the proposer
    # ranks the traversal one above the SSRF one for a traversal query.
    with db.connect() as conn:
        conn.execute("DELETE FROM reports WHERE external_id LIKE 'TEST-%'")
        conn.execute(
            "INSERT INTO reports (source, external_id, product, text) VALUES "
            "('test','TEST-TRAV','httpd','path traversal maps encoded ../ to files outside the document root, reading /etc/passwd'),"
            "('test','TEST-SSRF','httpd','server side request forgery in mod_proxy lets an attacker forward requests to internal hosts')"
        )
        ranked = search.candidates(conn, "directory path traversal reading /etc/passwd via encoded dot dot slash", limit=5)
        conn.execute("DELETE FROM reports WHERE external_id LIKE 'TEST-%'")

    ids = [c["external_id"] for c in ranked]
    assert ids and ids[0] == "TEST-TRAV", ranked
    assert ids.index("TEST-TRAV") < (ids.index("TEST-SSRF") if "TEST-SSRF" in ids else 99)


def test_scan_finds_fix_boundary():
    versions = ["2.4.49", "2.4.50", "2.4.51"]
    results = [run_replay("httpd", v, T41773) for v in versions]
    sr = verdict.scan_ladder(versions, results)
    assert sr.status == verdict.ALREADY_FIXED, sr.per_version
    assert sr.last_vulnerable == "2.4.49" and sr.fixed_in == "2.4.50", sr.per_version


def test_grafana_is_not_apache_specific():
    # A second, unrelated product (Grafana CVE-2021-43798) proves the engine is
    # vendor-agnostic: only a target spec and a template were added, no code.
    t = config.REPLAYS_DIR / "cve-2021-43798.yaml"
    v830 = run_replay("grafana", "8.3.0", t)
    v831 = run_replay("grafana", "8.3.1", t)
    assert v830.outcome == "pass" and v830.matched is True, v830.evidence
    assert v831.outcome == "fail" and v831.matched is False, v831.evidence
