"""Catalog of reports we can actually replay: their PoC template and fix boundary.

In production this comes from the team's own records (the fix commit/release linked
to each triaged report). Here it is a small seed so `/triage/auto` can go from an
incoming report straight to an execution verdict against the proposed candidate.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Runnable:
    product: str
    template: str
    pre_fix: str    # last version before the fix (the control)
    fixed_in: str   # first version with the fix


# Keyed by the candidate report's external id (what search returns).
RUNNABLE: dict[str, Runnable] = {
    "CVE-2021-41773": Runnable("httpd", "cve-2021-41773", "2.4.49", "2.4.50"),
    "CVE-2021-43798": Runnable("grafana", "cve-2021-43798", "8.3.0", "8.3.1"),
}


def get(external_id: str) -> Runnable | None:
    return RUNNABLE.get(external_id)
