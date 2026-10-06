"""fixproof Phase 0 API.

One endpoint stands up each requested httpd version, replays a PoC against it on
an egress-less network, and stores whether the state oracle matched. This is the
execution core the whole project is built on: `the LLM proposes, execution decides`.
Phase 0 has no LLM yet — the template is hand-written — but the decision already
comes from running the PoC, not from reading text.
"""
from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import config, db, verdict
from .runner import run_replay

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


class TriageRequest(BaseModel):
    product: str = "httpd"
    # the incoming report's PoC
    new_template: str
    # the earlier report we compare against, and its fix boundary
    candidate_template: str
    candidate_pre_fix: str   # last version before the candidate's fix (control)
    candidate_fixed_in: str  # first version with the candidate's fix


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
        "evidence": evidence,
    }


@app.get("/replays/{batch_id}")
def replays_get(batch_id: str) -> dict:
    with db.connect() as conn:
        rows = db.fetch_batch(conn, batch_id)
    if not rows:
        raise HTTPException(404, "batch not found")
    return {"batch_id": batch_id, "results": rows}
