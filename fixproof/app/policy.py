"""Turn a raw verdict into a disposition under a receiver's rules.

The verdict engine (app/verdict.py) says what the execution *means*: DUPLICATE,
BYPASS, REGRESSION, NOVEL, NOT_REPRODUCED. It does not say what to *do* about it —
whether to close the report as a duplicate, keep it open as its own issue, ask the
reporter for a working PoC, or route it to a human. That depends on the receiver's
counting rules, and those differ:

- CNA rule 4.1.9 / Intigriti: bugs that are "independently fixable" are separate, so
  a BYPASS is never merged into the report it bypassed.
- A conservative receiver auto-closes nothing: every merge is confirmed by a human.

Keeping this as declarative presets (not `if` branches scattered through the API)
means the counting rules are one readable place, and two safety invariants hold in
*every* preset because they are correctness properties, not preferences:

  * BYPASS and REGRESSION are never closed as duplicates — they are distinct bugs.
  * NOT_REPRODUCED and NEEDS_INFO never auto-close or auto-open anything — no
    reproducible evidence, no action. This is the gate against the 2026 wave of
    AI-generated reports that read well but run nothing.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import verdict as V

# --- dispositions (what to do) -------------------------------------------------
CLOSE_AS_DUPLICATE = "CLOSE_AS_DUPLICATE"  # merge into the candidate; same fix covers it
KEEP_OPEN = "KEEP_OPEN"                    # track as its own issue (bypass/regression/novel)
REQUEST_EVIDENCE = "REQUEST_EVIDENCE"      # no runnable evidence; ask the reporter for a PoC
HUMAN_REVIEW = "HUMAN_REVIEW"              # the engine could not conclude; a human decides


@dataclass
class Disposition:
    action: str
    rationale: str
    auto: bool          # may the system act without a human?
    needs_human: bool   # must a human confirm before anything irreversible?


@dataclass(frozen=True)
class Policy:
    name: str
    # May a confident DUPLICATE be closed automatically, or only proposed to a human?
    auto_close_duplicates: bool
    # May a distinct new bug (BYPASS / REGRESSION / NOVEL) be opened automatically,
    # or should a human triage it first?
    auto_open_new: bool
    description: str = ""


PRESETS: dict[str, Policy] = {
    # Balanced default: act on confident outcomes, hand the uncertain ones to a human.
    "default": Policy(
        name="default",
        auto_close_duplicates=True,
        auto_open_new=True,
        description="Auto-close confident duplicates, auto-open distinct bugs, request evidence when nothing reproduces.",
    ),
    # High-stakes intake: the engine proposes, a human confirms every state change.
    "conservative": Policy(
        name="conservative",
        auto_close_duplicates=False,
        auto_open_new=False,
        description="Never changes state automatically; every close and every new issue is human-confirmed.",
    ),
    # CNA counting rules: same knobs as default, but its rationale cites independent
    # fixability so a disputing reporter sees *why* a bypass was not merged.
    "cna": Policy(
        name="cna",
        auto_close_duplicates=True,
        auto_open_new=True,
        description="CVE counting rules: independently fixable bugs (bypass/regression) are always counted separately (rule 4.1.9).",
    ),
}

DEFAULT_POLICY = "default"


def get(name: str | None) -> Policy:
    """Resolve a preset by name, falling back to the default."""
    return PRESETS.get(name or DEFAULT_POLICY, PRESETS[DEFAULT_POLICY])


def apply(policy: Policy, v: V.Verdict) -> Disposition:
    """Map a verdict to a disposition under a policy. The two safety invariants are
    enforced here, above the policy knobs, so no preset can violate them."""
    label = v.label

    # --- evidence gate: nothing reproducible -> no state change, ask for a PoC ----
    if label in (V.NOT_REPRODUCED, V.NEEDS_INFO):
        return Disposition(
            REQUEST_EVIDENCE,
            "no reproducible evidence; the reporter is asked for a working PoC before any triage",
            auto=True,          # sending the request is safe to automate
            needs_human=False,
        )

    # --- engine could not conclude -> a human must look --------------------------
    if label == V.ABSTAIN:
        return Disposition(HUMAN_REVIEW, v.reason, auto=False, needs_human=True)

    # --- confident duplicate -> may close, depending on the policy ----------------
    if label == V.DUPLICATE:
        if policy.auto_close_duplicates:
            return Disposition(
                CLOSE_AS_DUPLICATE,
                "the candidate's fix also stops this PoC; same fix, same bug",
                auto=True,
                needs_human=False,
            )
        return Disposition(
            CLOSE_AS_DUPLICATE,
            "duplicate by execution; held for human confirmation under this policy",
            auto=False,
            needs_human=True,
        )

    # --- distinct new bug -> keep open; INVARIANT: never a duplicate --------------
    if label in (V.BYPASS, V.NOVEL, V.REGRESSION):
        why = {
            V.BYPASS: "survives the candidate's fix, so it is independently fixable and not a duplicate",
            V.REGRESSION: "a previously fixed bug that reproduces again; must not be closed as a duplicate",
            V.NOVEL: "reproduces but no known fix covers it; a new issue",
        }[label]
        if policy.name == "cna":
            why += " (CNA 4.1.9: independently fixable -> counted separately)"
        return Disposition(
            KEEP_OPEN,
            why,
            auto=policy.auto_open_new,
            needs_human=not policy.auto_open_new,
        )

    # Unknown label: fail safe to a human rather than guess.
    return Disposition(HUMAN_REVIEW, f"unrecognized verdict {label!r}", auto=False, needs_human=True)
