"""fixproof Phase 0 API.

One endpoint stands up each requested httpd version, replays a PoC against it on
an egress-less network, and stores whether the state oracle matched. This is the
execution core the whole project is built on: `the LLM proposes, execution decides`.
Phase 0 has no LLM yet — the template is hand-written — but the decision already
comes from running the PoC, not from reading text.
"""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import catalog, config, db, ingest, policy, search, targets, verdict
from .runner import ensure_patched_image, ensure_target_image, run_replay


def _disposition(policy_name: str | None, v: verdict.Verdict) -> dict:
    """Resolve the policy and map the verdict to a disposition for the response."""
    pol = policy.get(policy_name)
    d = policy.apply(pol, v)
    return {
        "policy": pol.name,
        "action": d.action,
        "rationale": d.rationale,
        "auto": d.auto,
        "needs_human": d.needs_human,
    }

app = FastAPI(title="FixProof", version="0.0.1")


@app.on_event("startup")
def _startup() -> None:
    db.init_schema()


class ReplayRequest(BaseModel):
    product: str = "httpd"
    template: str = "cve-2021-41773"
    versions: list[str] = Field(default_factory=lambda: ["2.4.49", "2.4.50"])


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/policies")
def policies() -> dict:
    """The available counting-rule presets a triage call can run under."""
    return {
        "default": policy.DEFAULT_POLICY,
        "presets": [
            {"name": p.name, "description": p.description,
             "auto_close_duplicates": p.auto_close_duplicates,
             "auto_open_new": p.auto_open_new}
            for p in policy.PRESETS.values()
        ],
    }


@app.post("/replays/run")
def replays_run(req: ReplayRequest) -> dict:
    template_path = config.REPLAYS_DIR / f"{req.template}.yaml"
    if not template_path.exists():
        raise HTTPException(404, f"template not found: {req.template}")

    batch_id = str(uuid.uuid4())
    results = []
    with db.connect() as conn:
        for version in req.versions:
            r = run_replay(req.product, version, template_path)
            db.record_run(
                conn,
                batch_id=batch_id,
                artifact_name=req.template,
                product=req.product,
                version=version,
                outcome=r.outcome,
                matched=r.matched,
                evidence=r.evidence,
                duration_ms=r.duration_ms,
            )
            results.append(
                {"version": version, "outcome": r.outcome, "matched": r.matched,
                 "duration_ms": r.duration_ms}
            )

    return {"batch_id": batch_id, "template": req.template, "results": results}


DEFAULT_CVES = [
    "CVE-2021-41773",  # httpd path traversal (our original)
    "CVE-2021-42013",  # httpd traversal bypass of the 2.4.50 fix
    "CVE-2021-40438",  # mod_proxy SSRF
    "CVE-2021-44790",  # mod_lua buffer overflow
    "CVE-2022-22720",  # HTTP request smuggling
    "CVE-2021-34798",  # NULL pointer dereference
]


class IngestRequest(BaseModel):
    cve_ids: list[str] = Field(default_factory=lambda: DEFAULT_CVES)


@app.post("/reports/ingest")
def reports_ingest(req: IngestRequest) -> dict:
    stored = ingest.ingest_cves(req.cve_ids)
    return {"stored": stored, "count": len(stored)}


class SearchRequest(BaseModel):
    text: str
    limit: int = 5
    exclude_external_id: str | None = None


@app.post("/search")
def search_candidates(req: SearchRequest) -> dict:
    with db.connect() as conn:
        results = search.candidates(
            conn, req.text, limit=req.limit, exclude_external_id=req.exclude_external_id
        )
    return {"query": req.text[:120], "candidates": results}


class TriageRequest(BaseModel):
    product: str = "httpd"
    # the incoming report's PoC
    new_template: str
    # the earlier report we compare against, and its fix boundary
    candidate_template: str
    candidate_pre_fix: str   # last version before the candidate's fix (control)
    candidate_fixed_in: str  # first version with the candidate's fix
    policy: str = policy.DEFAULT_POLICY  # receiver's counting rules


@app.post("/triage")
def triage(req: TriageRequest) -> dict:
    """Decide whether the new report is a duplicate of the candidate by running
    the new PoC before and after the candidate's fix."""
    template_path = config.REPLAYS_DIR / f"{req.new_template}.yaml"
    if not template_path.exists():
        raise HTTPException(404, f"template not found: {req.new_template}")

    pre = run_replay(req.product, req.candidate_pre_fix, template_path)
    post = run_replay(req.product, req.candidate_fixed_in, template_path)
    v = verdict.decide(pre, post)

    evidence = {
        "pre_fix": {"version": req.candidate_pre_fix, "outcome": pre.outcome, "matched": pre.matched},
        "post_fix": {"version": req.candidate_fixed_in, "outcome": post.outcome, "matched": post.matched},
    }
    with db.connect() as conn:
        db.record_verdict(
            conn,
            product=req.product,
            new_template=req.new_template,
            candidate_template=req.candidate_template,
            candidate_fixed_in=req.candidate_fixed_in,
            label=v.label,
            evidence=evidence,
        )

    return {
        "verdict": v.label,
        "reason": v.reason,
        "new_report": req.new_template,
        "candidate": req.candidate_template,
        "disposition": _disposition(req.policy, v),
        "evidence": evidence,
    }


class ScanRequest(BaseModel):
    product: str = "httpd"
    template: str
    # versions, oldest -> newest
    versions: list[str] = Field(default_factory=lambda: ["2.4.49", "2.4.50", "2.4.51"])


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    """Run one PoC across a version ladder and report the fix boundary and whether
    the bug still reproduces on the newest version (the 'already fixed?' answer)."""
    template_path = config.REPLAYS_DIR / f"{req.template}.yaml"
    if not template_path.exists():
        raise HTTPException(404, f"template not found: {req.template}")

    results = [run_replay(req.product, v, template_path) for v in req.versions]
    sr = verdict.scan_ladder(req.versions, results)
    return {
        "template": req.template,
        "status": sr.status,
        "last_vulnerable": sr.last_vulnerable,
        "fixed_in": sr.fixed_in,
        "regressed_in": sr.regressed_in,
        "per_version": sr.per_version,
    }


class VerifyFixRequest(BaseModel):
    product: str = "vulnapp"
    version: str = "1.0.0"   # the vulnerable build the PoC reproduces on
    template: str            # the PoC that reproduces the bug
    fix: str                 # named diff under targets/<product>/fixes/<fix>.patch


@app.post("/verify-fix")
def verify_fix(req: VerifyFixRequest) -> dict:
    """Patch-on-top: does a candidate fix actually stop the PoC? Runs it on the
    unpatched build (the control) and on the build with the fix diff applied on
    top. This verifies fixes that ship in no public version yet — the unreleased
    or internal patches an outside platform never sees."""
    template_path = config.REPLAYS_DIR / f"{req.template}.yaml"
    if not template_path.exists():
        raise HTTPException(404, f"template not found: {req.template}")
    patch_path = Path(targets.fix_path(req.product, req.fix))
    if not patch_path.exists():
        raise HTTPException(404, f"fix not found: {req.fix}")

    spec = targets.spec(req.product)
    base_image = ensure_target_image(spec, req.version)
    patched_image = ensure_patched_image(spec, base_image, patch_path)

    control = run_replay(req.product, req.version, template_path, image=base_image)
    patched = run_replay(req.product, f"{req.version}+{req.fix}", template_path, image=patched_image)
    v = verdict.verify_fix(control, patched)

    return {
        "verdict": v.label,
        "reason": v.reason,
        "product": req.product,
        "fix": req.fix,
        "evidence": {
            "unpatched": {"version": req.version, "outcome": control.outcome, "matched": control.matched},
            "patched": {"fix": req.fix, "outcome": patched.outcome, "matched": patched.matched},
        },
    }


class AutoTriageRequest(BaseModel):
    # the incoming report
    text: str                 # the report prose, used to search for candidates
    new_template: str         # the incoming report's replayable PoC
    product: str | None = None  # if omitted, taken from the chosen candidate
    policy: str = policy.DEFAULT_POLICY  # receiver's counting rules


@app.post("/triage/auto")
def triage_auto(req: AutoTriageRequest) -> dict:
    """The full loop: search proposes a candidate from the report text, then the
    engine runs the incoming PoC before and after that candidate's fix to decide."""
    template_path = config.REPLAYS_DIR / f"{req.new_template}.yaml"
    if not template_path.exists():
        raise HTTPException(404, f"template not found: {req.new_template}")

    with db.connect() as conn:
        ranked = search.candidates(conn, req.text, limit=5)

    # Pick the top-ranked candidate we can actually replay against.
    chosen = next((c for c in ranked if catalog.get(c["external_id"])), None)
    if chosen is None:
        # No candidate to run the fix-differential against. We cannot confirm NOVEL
        # here without a notion of "latest" per product, so we abstain honestly
        # rather than invent a verdict.
        nv = verdict.decide_no_candidate(None)
        return {"verdict": nv.label,
                "reason": nv.reason,
                "disposition": _disposition(req.policy, nv),
                "candidates": ranked}

    run = catalog.get(chosen["external_id"])
    product = req.product or run.product
    pre = run_replay(product, run.pre_fix, template_path)
    post = run_replay(product, run.fixed_in, template_path)
    v = verdict.decide(pre, post)

    evidence = {
        "pre_fix": {"version": run.pre_fix, "outcome": pre.outcome, "matched": pre.matched},
        "post_fix": {"version": run.fixed_in, "outcome": post.outcome, "matched": post.matched},
    }
    with db.connect() as conn:
        db.record_verdict(
            conn, product=product, new_template=req.new_template,
            candidate_template=run.template, candidate_fixed_in=run.fixed_in,
            label=v.label, evidence=evidence,
        )

    return {
        "verdict": v.label,
        "reason": v.reason,
        "chosen_candidate": chosen["external_id"],
        "candidate_score": chosen["score"],
        "new_report": req.new_template,
        "disposition": _disposition(req.policy, v),
        "evidence": evidence,
        "all_candidates": [c["external_id"] for c in ranked],
    }


@app.get("/replays/{batch_id}")
def replays_get(batch_id: str) -> dict:
    with db.connect() as conn:
        rows = db.fetch_batch(conn, batch_id)
    if not rows:
        raise HTTPException(404, "batch not found")
    return {"batch_id": batch_id, "results": rows}
