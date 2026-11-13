"""FixProof API.

Every endpoint answers a triage question by running a PoC, never by comparing
text: /triage (duplicate or bypass?), /scan (already fixed, and in which
version?), /verify-fix (does this unreleased patch stop it?) and /triage/auto
(search proposes a candidate, execution decides). `The LLM proposes, execution
decides` — there is no LLM in the loop yet, PoCs are hand-written templates, but
the decision already comes from execution.

The API has no authentication and it drives the Docker daemon, so it is meant to
listen on localhost only.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, StringConstraints

from . import catalog, config, db, ingest, policy, search, targets, verdict
from .runner import ensure_patched_image, ensure_target_image, run_replay

# Template, fix and product names become file paths, and versions become image
# tags and build args, so the request may only use a safe alphabet for them: no
# path separators, nothing the docker CLI could read as an option. A tool that
# replays path-traversal PoCs should not be traversable itself.
Name = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,99}$")]
Version = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
Versions = Annotated[list[Version], Field(min_length=1, max_length=20)]


def _contained(path: Path, root: Path) -> bool:
    return path.resolve().is_relative_to(root.resolve())


def _template_path(name: str) -> Path:
    """Resolve a PoC template by name, or 404. The containment check backs up the
    name pattern: the resolved file must live under the replays directory."""
    path = config.REPLAYS_DIR / f"{name}.yaml"
    if not _contained(path, config.REPLAYS_DIR) or not path.is_file():
        raise HTTPException(404, f"template not found: {name}")
    return path


def _require_product(product: str) -> targets.TargetSpec:
    if product not in targets.TARGETS:
        raise HTTPException(404, f"unknown product: {product}")
    return targets.TARGETS[product]


def _require_policy(name: str) -> policy.Policy:
    """An unknown policy is rejected, never replaced by the default: a typo in
    "conservative" must not turn into a policy that auto-closes."""
    try:
        return policy.get(name)
    except KeyError:
        raise HTTPException(422, f"unknown policy: {name}") from None


def _disposition(pol: policy.Policy, v: verdict.Verdict) -> dict:
    """Map the verdict to a disposition under the policy, for the response."""
    d = policy.apply(pol, v)
    return {
        "policy": pol.name,
        "action": d.action,
        "rationale": d.rationale,
        "auto": d.auto,
        "needs_human": d.needs_human,
    }

@asynccontextmanager
async def _lifespan(_: FastAPI):
    db.init_schema()
    yield


app = FastAPI(title="FixProof", version="0.0.1", lifespan=_lifespan)


class ReplayRequest(BaseModel):
    product: Name = "httpd"
    template: Name = "cve-2021-41773"
    versions: Versions = Field(default_factory=lambda: ["2.4.49", "2.4.50"])


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
    template_path = _template_path(req.template)
    _require_product(req.product)

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
    product: Name = "httpd"
    # the incoming report's PoC
    new_template: Name
    # the earlier report we compare against, and its fix boundary
    candidate_template: Name
    candidate_pre_fix: Version   # last version before the candidate's fix (control)
    candidate_fixed_in: Version  # first version with the candidate's fix
    policy: str = policy.DEFAULT_POLICY  # receiver's counting rules


@app.post("/triage")
def triage(req: TriageRequest) -> dict:
    """Decide whether the new report is a duplicate of the candidate by running
    the new PoC before and after the candidate's fix."""
    template_path = _template_path(req.new_template)
    _require_product(req.product)
    pol = _require_policy(req.policy)

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
        "disposition": _disposition(pol, v),
        "evidence": evidence,
    }


class ScanRequest(BaseModel):
    product: Name = "httpd"
    template: Name
    # versions, oldest -> newest
    versions: Versions = Field(default_factory=lambda: ["2.4.49", "2.4.50", "2.4.51"])


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    """Run one PoC across a version ladder and report the fix boundary and whether
    the bug still reproduces on the newest version (the 'already fixed?' answer)."""
    template_path = _template_path(req.template)
    _require_product(req.product)

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
    product: Name = "vulnapp"
    version: Version = "1.0.0"  # the vulnerable build the PoC reproduces on
    template: Name              # the PoC that reproduces the bug
    fix: Name                   # named diff under targets/<product>/fixes/<fix>.patch


@app.post("/verify-fix")
def verify_fix(req: VerifyFixRequest) -> dict:
    """Patch-on-top: does a candidate fix actually stop the PoC? Runs it on the
    unpatched build (the control) and on the build with the fix diff applied on
    top. This verifies fixes that ship in no public version yet — the unreleased
    or internal patches an outside platform never sees."""
    template_path = _template_path(req.template)
    spec = _require_product(req.product)
    patch_path = Path(targets.fix_path(req.product, req.fix))
    if not _contained(patch_path, config.TARGETS_DIR) or not patch_path.is_file():
        raise HTTPException(404, f"fix not found: {req.fix}")

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
    new_template: Name        # the incoming report's replayable PoC
    product: Name | None = None  # if omitted, taken from the chosen candidate
    policy: str = policy.DEFAULT_POLICY  # receiver's counting rules


@app.post("/triage/auto")
def triage_auto(req: AutoTriageRequest) -> dict:
    """The full loop: search proposes a candidate from the report text, then the
    engine runs the incoming PoC before and after that candidate's fix to decide."""
    template_path = _template_path(req.new_template)
    if req.product is not None:
        _require_product(req.product)
    pol = _require_policy(req.policy)

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
                "disposition": _disposition(pol, nv),
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
        "disposition": _disposition(pol, v),
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
