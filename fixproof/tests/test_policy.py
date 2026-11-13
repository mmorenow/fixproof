"""Unit tests for the policy layer. Pure logic — no Docker, no Postgres.
Run with: uv run pytest tests/test_policy.py
"""
from __future__ import annotations

import pytest

from app import policy, verdict


def _v(label: str) -> verdict.Verdict:
    return verdict.Verdict(label=label, reason="test")


# --- resolving presets ---------------------------------------------------------

def test_get_none_is_the_default():
    assert policy.get(None).name == policy.DEFAULT_POLICY


def test_get_unknown_preset_raises_instead_of_falling_back():
    # A typo in "conservative" must not silently become the auto-closing default.
    with pytest.raises(KeyError):
        policy.get("conservativ")


def test_get_known_preset():
    assert policy.get("conservative").name == "conservative"
    assert policy.get("cna").name == "cna"


# --- the default policy acts on confident outcomes ----------------------------

def test_default_auto_closes_duplicates():
    d = policy.apply(policy.get("default"), _v(verdict.DUPLICATE))
    assert d.action == policy.CLOSE_AS_DUPLICATE
    assert d.auto is True and d.needs_human is False


def test_default_auto_opens_new_bugs():
    for label in (verdict.BYPASS, verdict.REGRESSION, verdict.NOVEL):
        d = policy.apply(policy.get("default"), _v(label))
        assert d.action == policy.KEEP_OPEN
        assert d.auto is True and d.needs_human is False


# --- the conservative policy never changes state automatically ----------------

def test_conservative_proposes_but_never_auto_acts():
    pol = policy.get("conservative")
    dup = policy.apply(pol, _v(verdict.DUPLICATE))
    assert dup.action == policy.CLOSE_AS_DUPLICATE and dup.auto is False and dup.needs_human is True
    byp = policy.apply(pol, _v(verdict.BYPASS))
    assert byp.action == policy.KEEP_OPEN and byp.auto is False and byp.needs_human is True


# --- the evidence gate (anti AI-slop) -----------------------------------------

@pytest.mark.parametrize("label", [verdict.NOT_REPRODUCED, verdict.NEEDS_INFO])
def test_no_evidence_requests_evidence_under_every_preset(label):
    for name in policy.PRESETS:
        d = policy.apply(policy.get(name), _v(label))
        assert d.action == policy.REQUEST_EVIDENCE
        # Requesting evidence is safe to automate, and it is never a close/open.
        assert d.auto is True and d.needs_human is False


def test_abstain_always_goes_to_a_human():
    for name in policy.PRESETS:
        d = policy.apply(policy.get(name), _v(verdict.ABSTAIN))
        assert d.action == policy.HUMAN_REVIEW and d.needs_human is True


# --- safety invariants that must hold for EVERY preset ------------------------

def test_bypass_and_regression_are_never_closed_as_duplicate():
    for name in policy.PRESETS:
        for label in (verdict.BYPASS, verdict.REGRESSION):
            d = policy.apply(policy.get(name), _v(label))
            assert d.action != policy.CLOSE_AS_DUPLICATE, (name, label)


def test_no_evidence_never_closes_or_opens_under_any_preset():
    for name in policy.PRESETS:
        for label in (verdict.NOT_REPRODUCED, verdict.NEEDS_INFO):
            d = policy.apply(policy.get(name), _v(label))
            assert d.action not in (policy.CLOSE_AS_DUPLICATE, policy.KEEP_OPEN), (name, label)


def test_cna_rationale_cites_independent_fixability():
    d = policy.apply(policy.get("cna"), _v(verdict.BYPASS))
    assert "4.1.9" in d.rationale
