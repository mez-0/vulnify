"""EPSS (FIRST.org) batch enrichment."""

from __future__ import annotations

from urllib.parse import urlencode

from loguru import logger
from tqdm import tqdm

from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.http import fetch_json

EPSS_URL = "https://api.first.org/data/v1/epss"


def _chunks(ids: list[str], size: int) -> list[list[str]]:
    """
    Chunk a list of IDs into smaller lists.

    :param ids: The list of IDs to chunk.
    :type ids: list[str]
    :param size: The size of the chunks.
    :type size: int
    :return: The chunked list of IDs.
    :rtype: list[list[str]]
    """
    return [ids[i : i + size] for i in range(0, len(ids), size)]


async def enrich_epss_batch(
    store: SqliteCveStore, cve_ids: list[str], *, commit: bool = True
) -> int:
    """
    Fetch EPSS for up to 100 CVE IDs (comma-separated) and upsert scores.

    Writes directly to the ``intel`` table to avoid loading and re-serialising
    full :class:`~vulnify.models.cve.CVE` rows just to update two floats. When
    called from :func:`enrich_all_epss` we coalesce the per-batch commits to
    amortise WAL fsync — set ``commit=False`` to defer the COMMIT.

    :param store: The SQLite store to upsert the EPSS scores into.
    :type store: SqliteCveStore
    :param cve_ids: The list of CVE IDs to enrich.
    :type cve_ids: list[str]
    :param commit: If True, commit immediately. If False, the caller is
        responsible for committing the implicit transaction.
    :type commit: bool
    :return: Number of CVE rows updated.
    """
    if not cve_ids:
        return 0

    if not isinstance(store, SqliteCveStore):
        return 0

    q = urlencode([("cve", ",".join(cve_ids))])

    data = await fetch_json(f"{EPSS_URL}?{q}")

    if not isinstance(data, dict):
        return 0

    rows = data.get("data")

    if not isinstance(rows, list):
        logger.debug(f"EPSS: unexpected response: {data.get('status')}")
        return 0

    payload: list[tuple[str, float, float]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cid = str(row.get("cve", "") or "").strip()
        if not cid:
            continue
        try:
            score = float(row.get("epss") or 0.0)
            pct = float(row.get("percentile") or 0.0)
        except (TypeError, ValueError):
            continue
        payload.append((cid, score, pct))

    if not payload:
        return 0

    conn = store.connection
    cur = conn.cursor()
    placeholders = ",".join("?" * len(payload))
    cur.execute(
        f"SELECT cve_id FROM cve WHERE cve_id IN ({placeholders})",
        [t[0] for t in payload],
    )
    existing = {str(r[0]) for r in cur.fetchall()}
    filtered = [t for t in payload if t[0] in existing]
    if not filtered:
        return 0

    cur.executemany(
        """
        INSERT INTO intel (cve_id, epss_score, epss_percentile)
        VALUES (?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            epss_score = excluded.epss_score,
            epss_percentile = excluded.epss_percentile
        """,
        filtered,
    )
    if commit:
        conn.commit()
    return len(filtered)


async def enrich_all_epss(store) -> int:
    """
    Run batched EPSS for every ``cve_id`` in the database.

    EPSS scores update daily on the FIRST.org side, so cron-driven runs need
    to refresh the full corpus rather than skip already-scored rows. The
    UPSERT path is idempotent — repeated calls with unchanged scores are
    no-ops at the SQLite level.

    :param store: The SQLite store to upsert the EPSS scores into.
    :type store: SqliteCveStore
    :return: The number of CVE rows updated.
    :rtype: int
    """
    if not isinstance(store, SqliteCveStore):
        return 0
    cur = store.connection.execute("SELECT cve_id FROM cve ORDER BY cve_id")
    ids = [str(r[0]) for r in cur.fetchall()]
    if not ids:
        logger.info("EPSS: no CVE rows to refresh")
        return 0
    updated = 0
    pending_commits = 0
    # Each commit is an fsync. On a 700M+ WAL DB that's ~1s per commit, so
    # committing once per batch turns a 30 min phase into a 90 min phase.
    # Coalesce.
    EPSS_COMMITS_PER_BATCH = 50
    conn = store.connection
    try:
        for batch in tqdm(_chunks(ids, 100), desc="EPSS", unit="batch"):
            n = await enrich_epss_batch(store, batch, commit=False)
            updated += n
            pending_commits += 1
            if pending_commits >= EPSS_COMMITS_PER_BATCH:
                conn.commit()
                pending_commits = 0
        if pending_commits:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    logger.info(f"EPSS enrichment updated {updated} CVE rows")
    return updated


__all__ = ["EPSS_URL", "enrich_all_epss", "enrich_epss_batch"]
