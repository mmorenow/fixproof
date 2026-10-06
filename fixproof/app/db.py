"""Thin PostgreSQL helpers using psycopg3."""
from __future__ import annotations

import json
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

from . import config


def connect() -> psycopg.Connection:
    return psycopg.connect(config.DATABASE_URL, autocommit=True)


def init_schema() -> None:
    sql = (Path(__file__).parent / "schema.sql").read_text()
    with connect() as conn:
        conn.execute(sql)


def record_run(
    conn: psycopg.Connection,
    *,
    batch_id: str,
    artifact_name: str,
    product: str,
    version: str,
    outcome: str,
    matched: bool | None,
    evidence: dict,
    duration_ms: int,
) -> int:
    row = conn.execute(
        """
        INSERT INTO replay_runs
            (batch_id, artifact_name, product, version, outcome, matched, evidence, duration_ms)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (batch_id, artifact_name, product, version, outcome, matched, Jsonb(evidence), duration_ms),
    ).fetchone()
    return row[0]


def record_verdict(
    conn: psycopg.Connection,
    *,
    product: str,
    new_template: str,
    candidate_template: str,
    candidate_fixed_in: str,
    label: str,
    evidence: dict,
) -> int:
    row = conn.execute(
        """
        INSERT INTO verdicts
            (product, new_template, candidate_template, candidate_fixed_in, label, evidence)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (product, new_template, candidate_template, candidate_fixed_in, label, Jsonb(evidence)),
    ).fetchone()
    return row[0]


def fetch_batch(conn: psycopg.Connection, batch_id: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT version, outcome, matched, duration_ms, evidence
        FROM replay_runs
        WHERE batch_id = %s
        ORDER BY version
        """,
        (batch_id,),
    ).fetchall()
    return [
        {"version": r[0], "outcome": r[1], "matched": r[2], "duration_ms": r[3], "evidence": r[4]}
        for r in rows
    ]
