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

from . import config, db, ingest, search, verdict
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
        "per_version": sr.per_version,
    }


@app.get("/replays/{batch_id}")
def replays_get(batch_id: str) -> dict:
    with db.connect() as conn:
        rows = db.fetch_batch(conn, batch_id)
    if not rows:
        raise HTTPException(404, "batch not found")
    return {"batch_id": batch_id, "results": rows}
