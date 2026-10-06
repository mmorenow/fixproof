"""Candidate proposer: cheap lexical retrieval that suggests which earlier reports
a new report might duplicate. It never decides — it only narrows the field so the
execution engine (triage) runs the fix-differential against a handful of candidates
instead of the whole history.

Score = full-text rank (ts_rank) blended with trigram similarity. Full-text catches
shared terms; trigram catches fuzzy overlap the stemmer misses. Embeddings/pgvector
are the richer next step; this lexical pass is the honest baseline the GitLab
pgvector experiment found "good for similar, not for duplicate".
"""
from __future__ import annotations

import psycopg


def candidates(conn: psycopg.Connection, query_text: str, *, limit: int = 5,
               exclude_external_id: str | None = None) -> list[dict]:
    rows = conn.execute(
        """
        SELECT external_id, product,
               ts_rank(search, plainto_tsquery('english', %(q)s)) AS fts,
               similarity(text, %(q)s) AS trgm,
               left(text, 160) AS snippet
        FROM reports
        WHERE (%(exclude)s::text IS NULL OR external_id <> %(exclude)s::text)
          AND (search @@ plainto_tsquery('english', %(q)s)
               OR similarity(text, %(q)s) > 0.05)
        ORDER BY (ts_rank(search, plainto_tsquery('english', %(q)s)) * 2
                  + similarity(text, %(q)s)) DESC
        LIMIT %(limit)s
        """,
        {"q": query_text, "exclude": exclude_external_id, "limit": limit},
    ).fetchall()
    return [
        {"external_id": r[0], "product": r[1],
         "score": round(float(r[2]) * 2 + float(r[3]), 4),
         "fts": round(float(r[2]), 4), "trgm": round(float(r[3]), 4),
         "snippet": r[4]}
        for r in rows
    ]
