"""EPSS (FIRST.org) batch enrichment."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlencode

from loguru import logger
from tqdm import tqdm

from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.http import fetch_json_maybe

EPSS_URL = "https://api.first.org/data/v1/epss"

# FIRST's API answers 502/504 in bursts. Before retries were wired in, one bad
# response dropped a whole 100-CVE batch: ~7 batches across two runs of the
# 2026-11-02 build, and the phase still reported success. Backoff of 2+4+8s
# rides out a blip in place...
EPSS_MAX_ATTEMPTS = 4

# ...but the bursts came in runs of consecutive batches (3684-3686 in one run),
# longer than any sensible in-place backoff. Batches still failing after the main
# pass get one more attempt at the end of the phase, minutes later.
EPSS_DEFERRED_RETRY_PASSES = 1

EPSS_BATCH_SIZE = 100

# ``(body, error)`` — ``error`` is None on success. Injectable so tests can
# drive the failure paths without a network.
EpssFetch = Callable[[str], Awaitable[tuple[dict[str, Any], str | None]]]


async def _fetch_epss(url: str) -> tuple[dict[str, Any], str | None]:
    return await fetch_json_maybe(url, max_attempts=EPSS_MAX_ATTEMPTS)


def _batch_label(cve_ids: list[str]) -> str:
    return f"{cve_ids[0]}..{cve_ids[-1]} ({len(cve_ids)} CVEs)"


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
    store: SqliteCveStore,
    cve_ids: list[str],
    *,
    commit: bool = True,
    fetch: EpssFetch = _fetch_epss,
) -> int | None:
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
    :param fetch: Fetcher returning ``(body, error)``; defaults to FIRST with
        retries.
    :return: Number of CVE rows updated, or ``None`` if the fetch failed. A
        failed fetch writes nothing, so existing scores survive it.
    """
    if not cve_ids:
        return 0

    if not isinstance(store, SqliteCveStore):
        return 0

    q = urlencode([("cve", ",".join(cve_ids))])

    data, err = await fetch(f"{EPSS_URL}?{q}")
    if err is not None:
        logger.warning(f"EPSS: fetch failed for {_batch_label(cve_ids)}: {err}")
        return None

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
        # A row without a score is "not scored" — skip it so the column stays
        # NULL. ``or 0.0`` here would invent a negligible score.
        if row.get("epss") is None or row.get("percentile") is None:
            continue
        try:
            score = float(row["epss"])
            pct = float(row["percentile"])
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


async def enrich_all_epss(store, *, fetch: EpssFetch = _fetch_epss) -> int:
    """
    Run batched EPSS for every ``cve_id`` in the database.

    EPSS scores update daily on the FIRST.org side, so cron-driven runs need
    to refresh the full corpus rather than skip already-scored rows. The
    UPSERT path is idempotent — repeated calls with unchanged scores are
    no-ops at the SQLite level.

    Batches whose fetch fails (after in-place retries) are retried once more at
    the end of the phase; any still failing are reported in a closing warning
    rather than buried in the per-batch log. They keep whatever score they had.

    :param store: The SQLite store to upsert the EPSS scores into.
    :type store: SqliteCveStore
    :param fetch: Fetcher returning ``(body, error)``; defaults to FIRST with
        retries.
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

    updated, failed = await _run_batches(
        store, _chunks(ids, EPSS_BATCH_SIZE), fetch=fetch, desc="EPSS"
    )
    for _ in range(EPSS_DEFERRED_RETRY_PASSES):
        if not failed:
            break
        logger.info(f"EPSS: retrying {len(failed)} failed batch(es)")
        n, failed = await _run_batches(store, failed, fetch=fetch, desc="EPSS retry")
        updated += n

    logger.info(f"EPSS enrichment updated {updated} CVE rows")
    if failed:
        lost = sum(len(b) for b in failed)
        logger.warning(
            f"EPSS: {len(failed)} batch(es) / {lost} CVEs still failing after "
            f"retries; their scores were not refreshed (existing values kept, "
            f"unscored ones stay NULL). First: {_batch_label(failed[0])}"
        )
    return updated


async def _run_batches(
    store: SqliteCveStore,
    batches: list[list[str]],
    *,
    fetch: EpssFetch,
    desc: str,
) -> tuple[int, list[list[str]]]:
    """Fetch and upsert each batch; return ``(rows updated, failed batches)``."""
    updated = 0
    failed: list[list[str]] = []
    pending_commits = 0
    # Each commit is an fsync. On a 700M+ WAL DB that's ~1s per commit, so
    # committing once per batch turns a 30 min phase into a 90 min phase.
    # Coalesce.
    EPSS_COMMITS_PER_BATCH = 50
    conn = store.connection
    try:
        for batch in tqdm(batches, desc=desc, unit="batch"):
            n = await enrich_epss_batch(store, batch, commit=False, fetch=fetch)
            if n is None:
                failed.append(batch)
                continue
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
    return updated, failed


__all__ = ["EPSS_URL", "enrich_all_epss", "enrich_epss_batch"]
