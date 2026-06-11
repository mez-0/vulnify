"""OSV (Open Source Vulnerabilities) package context per CVE."""

from __future__ import annotations

import asyncio
from typing import Any

from loguru import logger
from tqdm import tqdm

from vulnify.db.sqlite_store import SqliteCveStore

from vulnify.http import fetch_json_maybe
from vulnify.providers.enrichment_resume import cve_ids_pending_osv

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"

# OSV has no batch-by-CVE-id endpoint, so every CVE is a separate GET. Run them
# concurrently (the work is pure network round-trip) and persist in batches.
OSV_CONCURRENCY = 50
OSV_BATCH_SIZE = 1000
OSV_MAX_ATTEMPTS = 3


def _packages_from_osv(doc: dict[str, Any]) -> list[str]:
    """
    Get the packages from the OSV document.

    :param doc: The OSV document.
    :type doc: dict[str, Any]
    :return: The packages from the OSV document.
    :rtype: list[str]
    """
    out: list[str] = []
    for aff in doc.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package")
        if not isinstance(pkg, dict):
            continue
        eco = str(pkg.get("ecosystem", "") or "").strip()
        name = str(pkg.get("name", "") or "").strip()
        if eco and name:
            out.append(f"{eco}:{name}")
    return sorted(set(out))


async def fetch_osv_packages_for_cve(cve_id: str) -> tuple[list[str], bool]:
    """Fetch OSV document and return affected ``ecosystem:package`` strings.

    OSV returns HTTP 404 for CVE IDs not in its bucket; that's the common case
    and isn't worth logging at WARN/ERROR. The second tuple element is whether
    the result is *authoritative* — ``True`` for a 200 or 404 (the CVE was
    conclusively checked), ``False`` for a transient failure (timeout, 429,
    5xx) where the CVE should be retried on a later run rather than recorded as
    empty.

    :param cve_id: The CVE ID.
    :type cve_id: str
    :return: ``(packages, authoritative)``.
    :rtype: tuple[list[str], bool]
    """
    url = OSV_VULN_URL.format(id=cve_id.strip())
    data, err = await fetch_json_maybe(
        url, max_attempts=OSV_MAX_ATTEMPTS, log_retries=False
    )
    if err is None:
        return _packages_from_osv(data), True
    if err.startswith("HTTP 404"):
        return [], True
    logger.warning("OSV: {cve} fetch failed: {detail}", cve=cve_id, detail=err)
    return [], False


def _persist_osv_result(
    cur, cve_id: str, packages: list[str], authoritative: bool
) -> bool:
    """Write OSV packages plus an ``osv_checked`` marker for one CVE.

    The marker records that the CVE was conclusively checked so that the
    ~99% of CVEs with no OSV entry aren't re-queried on every run. It is only
    written when ``authoritative`` is true; transient failures leave the CVE
    pending. Does not commit — the caller owns the transaction.

    :return: True if at least one new OSV package row was inserted.
    :rtype: bool
    """
    new_pkg = False
    if packages:
        cur.executemany(
            """
            INSERT OR IGNORE INTO intel_string_list (cve_id, kind, value)
            VALUES (?, 'osv_package', ?)
            """,
            [(cve_id, p) for p in packages],
        )
        new_pkg = cur.rowcount > 0
    if authoritative:
        cur.execute(
            """
            INSERT OR IGNORE INTO intel_string_list (cve_id, kind, value)
            VALUES (?, 'osv_checked', '1')
            """,
            (cve_id,),
        )
    return new_pkg


async def enrich_osv_for_cve(store, cve_id: str) -> bool:
    """
    Enrich the OSV for a single CVE.

    Inserts directly into ``intel_string_list`` to avoid loading and rewriting
    the full CVE graph for what is usually a no-op (most CVEs aren't in OSV).

    :param store: The SQLite store to upsert the OSV packages into.
    :type store: SqliteCveStore
    :param cve_id: The CVE ID.
    :type cve_id: str
    :return: True if at least one new OSV package row was inserted.
    :rtype: bool
    """

    if not isinstance(store, SqliteCveStore):
        return False
    cid = (cve_id or "").strip()
    if not cid:
        return False
    packages, authoritative = await fetch_osv_packages_for_cve(cid)

    conn = store.connection
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM cve WHERE cve_id = ? LIMIT 1", (cid,))
    if cur.fetchone() is None:
        return False
    try:
        cur.execute("BEGIN")
        new_pkg = _persist_osv_result(cur, cid, packages, authoritative)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return new_pkg


async def enrich_all_osv(store) -> int:
    """OSV enrichment for every CVE in the database.

    Each pending CVE is a separate ``/v1/vulns/{id}`` lookup, so the fetches run
    concurrently (bounded by :data:`OSV_CONCURRENCY`) and results are persisted
    in batches of :data:`OSV_BATCH_SIZE`. Conclusively-checked CVEs — including
    the ~99% that aren't in OSV — get an ``osv_checked`` marker so subsequent
    runs only query genuinely new CVEs.

    :param store: The SQLite store to upsert the OSV packages into.
    :type store: SqliteCveStore
    :return: The number of CVE rows updated with package data.
    :rtype: int
    """
    if not isinstance(store, SqliteCveStore):
        return 0
    ids, cve_total = cve_ids_pending_osv(store.connection)
    skipped = cve_total - len(ids)
    if skipped:
        logger.info(
            "OSV: skipping {skipped} already-checked CVE rows ({pending} pending)",
            skipped=skipped,
            pending=len(ids),
        )
    if not ids:
        logger.info("OSV: nothing pending")
        return 0

    conn = store.connection
    sem = asyncio.Semaphore(OSV_CONCURRENCY)

    async def _fetch(cid: str) -> tuple[str, list[str], bool]:
        async with sem:
            packages, authoritative = await fetch_osv_packages_for_cve(cid)
        return cid, packages, authoritative

    n = 0
    with tqdm(total=len(ids), desc="OSV", unit="CVE") as pbar:
        for start in range(0, len(ids), OSV_BATCH_SIZE):
            chunk = ids[start : start + OSV_BATCH_SIZE]
            results = await asyncio.gather(*(_fetch(c) for c in chunk))
            cur = conn.cursor()
            try:
                cur.execute("BEGIN")
                for cid, packages, authoritative in results:
                    if _persist_osv_result(cur, cid, packages, authoritative):
                        n += 1
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            pbar.update(len(chunk))
    logger.info(f"OSV enrichment touched {n} CVE rows with package data")
    return n


__all__ = [
    "OSV_VULN_URL",
    "enrich_all_osv",
    "fetch_osv_packages_for_cve",
    "enrich_osv_for_cve",
]
