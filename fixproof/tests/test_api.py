"""API input handling. Pure — no Docker, no Postgres: every request here is
rejected before anything is executed. Run with: uv run pytest tests/test_api.py

Template, fix and product names from a request become file paths, and versions
become image tags, so the API must refuse anything that could escape its
directories or reach the docker CLI as an option.
"""
from __future__ import annotations

import subprocess

import pytest
from fastapi.testclient import TestClient

from app import main, runner

# No `with`: the lifespan (which needs Postgres) is not run for these tests.
client = TestClient(main.app)


@pytest.fixture(autouse=True)
def _no_execution(monkeypatch):
    """Fail loudly if a request that should be rejected reaches the engine."""
    def _boom(*args, **kwargs):
        raise AssertionError("a rejected request reached the execution engine")

    for name in ("run_replay", "ensure_target_image", "ensure_patched_image"):
        monkeypatch.setattr(main, name, _boom)


TRAVERSALS = ["../../etc/passwd", "..%2f..%2fetc%2fpasswd", "/etc/passwd", "a/b", "..", "-rf", ""]


@pytest.mark.parametrize("name", TRAVERSALS)
def test_template_name_cannot_leave_the_replays_dir(name):
    r = client.post("/scan", json={"template": name})
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("name", TRAVERSALS)
def test_fix_name_cannot_leave_the_targets_dir(name):
    r = client.post("/verify-fix", json={"template": "vulnapp-path-traversal", "fix": name})
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("version", ["--privileged", "2.4.49 --foo", "a/b", "$(id)", ""])
def test_version_must_be_a_plain_tag(version):
    r = client.post("/scan", json={"template": "cve-2021-41773", "versions": [version]})
    assert r.status_code == 422, r.text


def test_version_ladder_is_bounded():
    r = client.post("/scan", json={"template": "cve-2021-41773", "versions": ["1"] * 21})
    assert r.status_code == 422, r.text


def test_unknown_template_is_404():
    r = client.post("/scan", json={"template": "no-such-template"})
    assert r.status_code == 404, r.text


def test_unknown_product_is_404_not_a_crash():
    r = client.post("/scan", json={"product": "no-such-product", "template": "cve-2021-41773"})
    assert r.status_code == 404, r.text


def test_unknown_fix_is_404():
    r = client.post("/verify-fix", json={"template": "vulnapp-path-traversal", "fix": "no-such-fix"})
    assert r.status_code == 404, r.text


def test_unknown_policy_is_rejected_before_anything_runs():
    # A typo must not fall back to the auto-closing default policy.
    r = client.post("/triage", json={
        "new_template": "cve-2021-42013", "candidate_template": "cve-2021-41773",
        "candidate_pre_fix": "2.4.49", "candidate_fixed_in": "2.4.50",
        "policy": "conservativ",
    })
    assert r.status_code == 422, r.text


def test_docker_timeout_is_an_error_outcome_not_a_crash(monkeypatch):
    # A hung docker call must surface as DockerError (-> outcome `error`, and the
    # verdict engine abstains), never as an unhandled TimeoutExpired.
    def _hang(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

    monkeypatch.setattr(runner.subprocess, "run", _hang)
    with pytest.raises(runner.DockerError):
        runner._docker("run", "busybox", timeout=1)
