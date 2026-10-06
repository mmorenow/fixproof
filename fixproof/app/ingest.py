"""Pull real, public vulnerability descriptions from OSV (osv.dev) and store them
as reports. This gives the candidate proposer real text to rank over, from a
project (Apache httpd) that actually received these reports.
"""
from __future__ import annotations

import httpx

from . import db

OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"


def fetch_osv(cve_id: str) -> dict | None:
    r = httpx.get(OSV_VULN.format(id=cve_id), timeout=15)
    if r.status_code != 200:
        return None
    d = r.json()
    text = " ".join(filter(None, [d.get("summary"), d.get("details")])).strip()
    if not text:
        return None
    return {
        "source": "osv",
        "external_id": d.get("id", cve_id),
        "product": "httpd",
        "text": text,
        "published_at": d.get("published"),
    }


def ingest_cves(cve_ids: list[str]) -> list[str]:
    """Fetch each CVE from OSV and upsert it. Returns the ids actually stored."""
    stored = []
    with db.connect() as conn:
        for cve in cve_ids:
            rec = fetch_osv(cve)
            if rec is None:
                continue
            conn.execute(
                """
                INSERT INTO reports (source, external_id, product, text, published_at)
                VALUES (%(source)s, %(external_id)s, %(product)s, %(text)s, %(published_at)s)
                ON CONFLICT (external_id) DO UPDATE SET text = EXCLUDED.text
                """,
                rec,
            )
            stored.append(rec["external_id"])
    return stored
