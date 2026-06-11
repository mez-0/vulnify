"""Per-phase resume state for cron-driven incremental enrichment runs.

Each enrichment phase records the timestamp of its last successful run plus a
phase-specific ``watermark`` string used to scope the next run:

* ``nvd_bulk`` watermark — ISO 8601 ``lastModified`` upper bound carried into
  NVD's ``lastModStartDate`` query parameter on the next run.
* ``kev`` watermark — the CISA catalog ``catalogVersion`` last ingested; used
  to short-circuit when the upstream catalog hasn't moved.
"""

from __future__ import annotations

import sqlite3


def get_phase_state(
    conn: sqlite3.Connection, phase: str
) -> tuple[str | None, str | None]:
    """
    Return the last completion timestamp and watermark for ``phase``.

    :param conn: An open SQLite connection.
    :type conn: sqlite3.Connection
    :param phase: The phase name (e.g. ``"nvd_bulk"``).
    :type phase: str
    :return: ``(last_completed_at, last_watermark)``. Both are ``None`` when
        the phase has never completed.
    :rtype: tuple[str | None, str | None]
    """
    cur = conn.execute(
        "SELECT last_completed_at, last_watermark FROM pipeline_run WHERE phase = ?",
        (phase,),
    )
    row = cur.fetchone()
    if row is None:
        return None, None
    completed = None if row[0] is None else str(row[0])
    watermark = None if row[1] is None else str(row[1])
    return completed, watermark


def set_phase_state(
    conn: sqlite3.Connection,
    phase: str,
    *,
    completed_at: str,
    watermark: str | None = None,
) -> None:
    """
    Upsert ``(phase, completed_at, watermark)`` into ``pipeline_run``.

    The caller owns the surrounding transaction — this function does not
    commit. Pair it with the same commit boundary that wrote the phase's
    row updates.

    :param conn: An open SQLite connection.
    :type conn: sqlite3.Connection
    :param phase: The phase name.
    :type phase: str
    :param completed_at: ISO 8601 timestamp of completion.
    :type completed_at: str
    :param watermark: Phase-specific resume marker.
    :type watermark: str | None
    """
    conn.execute(
        """
        INSERT INTO pipeline_run (phase, last_completed_at, last_watermark)
        VALUES (?, ?, ?)
        ON CONFLICT(phase) DO UPDATE SET
            last_completed_at = excluded.last_completed_at,
            last_watermark = excluded.last_watermark
        """,
        (phase, completed_at, watermark),
    )


__all__ = ["get_phase_state", "set_phase_state"]
