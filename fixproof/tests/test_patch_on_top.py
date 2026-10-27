"""Patch-on-top, end to end. Requires Docker.

Builds the deliberately vulnerable internal app, confirms the PoC reproduces on it
(the control), applies the team's unreleased fix diff on top of that built image,
and confirms the same PoC now fails. This is the case no outside platform can serve:
there is no CVE and no public version — only a private patch — and execution still
decides. Run with: uv run pytest tests/test_patch_on_top.py -s
"""
from __future__ import annotations

from pathlib import Path

from app import config, targets, verdict
from app.runner import ensure_patched_image, ensure_target_image, run_replay

T = config.REPLAYS_DIR / "vulnapp-path-traversal.yaml"


def test_patch_on_top_confirms_unreleased_fix():
    spec = targets.spec("vulnapp")
    base = ensure_target_image(spec, "1.0.0")
    patch = Path(targets.fix_path("vulnapp", "path-traversal"))
    patched = ensure_patched_image(spec, base, patch)

    control = run_replay("vulnapp", "1.0.0", T, image=base)
    after = run_replay("vulnapp", "1.0.0+path-traversal", T, image=patched)

    # The PoC reads the canary outside the web root on the unpatched build, and the
    # unreleased fix stops it — proven by running it, not by reading the diff.
    assert control.outcome == "pass" and control.matched is True, control.evidence
    assert after.outcome == "fail" and after.matched is False, after.evidence
    assert verdict.verify_fix(control, after).label == verdict.FIX_CONFIRMED
