"""Post–CVE-bulk enrichment: KEV catalog, NVD, vendor index, EPSS, OSV, vendor stub."""

from __future__ import annotations

import asyncio
import math
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from loguru import logger
from tqdm import tqdm

from vulnify.db.pipeline_state import get_phase_state, set_phase_state
from vulnify.providers.cisa_kev import ingest_cisa_kev_catalog
from vulnify.providers.epss import enrich_all_epss
from vulnify.providers.nvd import (
    NVD_BULK_RESULTS_PER_PAGE,
    fetch_nvd_page,
    merge_nvd_cve_into_db,
)
from vulnify.providers.exploit_ingest import (
    ingest_exploitdb,
    ingest_metasploit,
    ingest_nuclei_templates,
    write_back_exploit_bools,
)
from vulnify.providers.osv import enrich_all_osv
from vulnify.providers.vendor_advisories import process_vendor_advisories
from vulnify.providers.placeholder_products import refresh_placeholder_products
from vulnify.providers.vendor_index import refresh_vendor_index
from vulnify.settings import get_nvd_api_key

if TYPE_CHECKING:
    from vulnify.db.sqlite_store import SqliteCveStore

# Public NVD 2.0 API: ~5 req / 30s without a key; ~50 req / 30s with ``VULNIFY_NVD_API_KEY``.
NVD_PUBLIC_REQUEST_DELAY_SEC = 6.0
NVD_KEYED_REQUEST_DELAY_SEC = 0.65

# Pages between WAL fsyncs. Each commit flushes ~10k merged CVEs, keeping the
# WAL bounded without forcing an fsync on every page.
NVD_BULK_COMMIT_EVERY_N_PAGES = 5

# NVD enforces a 120-day max span per ``lastModStartDate``/``lastModEndDate``
# query. We use 119 days to keep a safety margin against clock skew between
# our clock and NVD's index.
NVD_LAST_MOD_WINDOW_DAYS = 119

NVD_PIPELINE_PHASE = "nvd_bulk"


def _split_last_mod_windows(
    start_iso: str, end_iso: str
) -> list[tuple[str, str]]:
    """
    Split ``[start, end]`` into windows no longer than NVD's 120-day cap.

    :param start_iso: ISO 8601 UTC lower bound (inclusive).
    :type start_iso: str
    :param end_iso: ISO 8601 UTC upper bound (inclusive).
    :type end_iso: str
    :return: Ordered list of ``(start, end)`` ISO timestamp pairs covering
        the full range. Empty when ``start >= end``.
    :rtype: list[tuple[str, str]]
    """
    start = datetime.fromisoformat(start_iso)
    end = datetime.fromisoformat(end_iso)
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if start >= end:
        return []
    span = timedelta(days=NVD_LAST_MOD_WINDOW_DAYS)
    windows: list[tuple[str, str]] = []
    cursor = start
    while cursor < end:
        nxt = min(cursor + span, end)
        windows.append(
            (
                cursor.isoformat(timespec="seconds"),
                nxt.isoformat(timespec="seconds"),
            )
        )
        cursor = nxt
    return windows


async def _paginate_nvd(
    store: SqliteCveStore,
    delay: float,
    *,
    last_mod_start: str | None = None,
    last_mod_end: str | None = None,
    desc: str = "NVD bulk",
) -> int:
    """
    Walk every page of an NVD 2.0 listing window and merge each CVE.

    :param store: The SQLite store.
    :type store: SqliteCveStore
    :param delay: Seconds to sleep between page requests.
    :type delay: float
    :param last_mod_start: Optional inclusive ``lastModified`` lower bound.
    :type last_mod_start: str | None
    :param last_mod_end: Optional inclusive ``lastModified`` upper bound.
    :type last_mod_end: str | None
    :param desc: tqdm progress label.
    :type desc: str
    :return: Number of CVE rows merged.
    :rtype: int
    """
    first, err = await fetch_nvd_page(
        0,
        last_mod_start_date=last_mod_start,
        last_mod_end_date=last_mod_end,
    )
    if err is not None:
        logger.error("NVD bulk: first page fetch failed: {detail}", detail=err)
        return 0

    total = int(first.get("totalResults") or 0)
    page_size = int(first.get("resultsPerPage") or NVD_BULK_RESULTS_PER_PAGE)
    if total == 0:
        logger.info("NVD bulk: 0 records in window")
        return 0
    if page_size <= 0:
        logger.warning("NVD bulk: malformed first page response")
        return 0

    pages = math.ceil(total / page_size)
    logger.info(
        "NVD bulk: {total:,} CVE records across {pages} page(s) "
        "(~{eta_min:.0f} min at {delay:.2f}s/page)",
        total=total,
        pages=pages,
        eta_min=(pages * delay) / 60.0,
        delay=delay,
    )

    conn = store.connection
    updated = 0
    pending_commits = 0

    def _apply_page(doc: dict) -> int:
        n = 0
        vulns = doc.get("vulnerabilities")
        if not isinstance(vulns, list):
            return 0
        for entry in vulns:
            if not isinstance(entry, dict):
                continue
            nvd_cve = entry.get("cve")
            if not isinstance(nvd_cve, dict):
                continue
            if merge_nvd_cve_into_db(conn, nvd_cve):
                n += 1
        return n

    try:
        with tqdm(total=pages, desc=desc, unit="page") as pbar:
            updated += _apply_page(first)
            pbar.update(1)
            pending_commits += 1
            if pending_commits >= NVD_BULK_COMMIT_EVERY_N_PAGES:
                conn.commit()
                pending_commits = 0

            for page_idx in range(1, pages):
                await asyncio.sleep(delay)
                doc, page_err = await fetch_nvd_page(
                    page_idx * page_size,
                    last_mod_start_date=last_mod_start,
                    last_mod_end_date=last_mod_end,
                )
                if page_err is not None:
                    logger.warning(
                        "NVD bulk: page {idx} failed after retries: {detail}",
                        idx=page_idx,
                        detail=page_err,
                    )
                    pbar.update(1)
                    continue
                updated += _apply_page(doc)
                pbar.update(1)
                pending_commits += 1
                if pending_commits >= NVD_BULK_COMMIT_EVERY_N_PAGES:
                    conn.commit()
                    pending_commits = 0
        if pending_commits:
            conn.commit()
    except Exception:
        conn.rollback()
        raise

    return updated


async def enrich_all_nvd(store: SqliteCveStore, *, full: bool = False) -> int:
    """
    Bulk-paginate the NVD 2.0 ``/cves/2.0`` listing and merge each record
    directly into the SQLite store.

    The first run (no ``pipeline_run`` watermark) walks the entire listing —
    ~150 calls × 2000 records ≈ 30 minutes on the public throttle. Every
    subsequent run reads the previous watermark from ``pipeline_run`` and
    queries only CVEs modified since, splitting into 119-day windows when
    the gap exceeds NVD's 120-day cap. A daily cron typically pulls a few
    pages of deltas in seconds.

    🚨 **The watermark is only valid while the rows it covers still exist.**
    Ingestion cascade-wipes every re-ingested CVE's ``cpe_match`` / ``cvss`` /
    NVD fields, and an incremental refresh only re-fetches CVEs *NVD* modified
    since — so after an ingest it heals a fraction of what was wiped and leaves
    the rest empty. Measured: a gather after a snapshot bump took ``cpe_match``
    from 1.3M rows to 169k. Pass ``full=True`` whenever ingestion ran.

    :param store: The SQLite store to merge NVD records into.
    :type store: SqliteCveStore
    :param full: Ignore the watermark and walk the entire listing.
    :type full: bool
    :return: The number of CVE rows merged.
    :rtype: int
    """
    has_key = bool(get_nvd_api_key())
    delay = NVD_KEYED_REQUEST_DELAY_SEC if has_key else NVD_PUBLIC_REQUEST_DELAY_SEC

    _, last_watermark = get_phase_state(store.connection, NVD_PIPELINE_PHASE)
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if full or last_watermark is None:
        logger.info(
            "NVD bulk: {why}; running full backfill",
            why="ingestion ran" if full else "no prior watermark",
        )
        merged = await _paginate_nvd(store, delay)
    else:
        windows = _split_last_mod_windows(last_watermark, now_iso)
        if not windows:
            logger.info(
                "NVD bulk: caught up at {wm} (nothing to refresh)",
                wm=last_watermark,
            )
            set_phase_state(
                store.connection,
                NVD_PIPELINE_PHASE,
                completed_at=now_iso,
                watermark=now_iso,
            )
            store.connection.commit()
            return 0
        logger.info(
            "NVD bulk: incremental refresh from {wm} ({n} window(s))",
            wm=last_watermark,
            n=len(windows),
        )
        merged = 0
        for idx, (start, end) in enumerate(windows, start=1):
            label = "NVD bulk" if len(windows) == 1 else f"NVD bulk {idx}/{len(windows)}"
            merged += await _paginate_nvd(
                store,
                delay,
                last_mod_start=start,
                last_mod_end=end,
                desc=label,
            )

    set_phase_state(
        store.connection,
        NVD_PIPELINE_PHASE,
        completed_at=now_iso,
        watermark=now_iso,
    )
    store.connection.commit()
    logger.info(f"NVD bulk enrichment merged {merged} CVE records")
    return merged


async def run_post_ingestion_enrichment(
    store: SqliteCveStore | None,
    *,
    skip_kev: bool = False,
    skip_nvd: bool = False,
    skip_vendor_index: bool = False,
    skip_placeholder_products: bool = False,
    skip_epss: bool = False,
    skip_osv: bool = False,
    skip_nuclei: bool = False,
    skip_exploitdb: bool = False,
    skip_metasploit: bool = False,
    ingestion_ran: bool = True,
) -> None:
    """
    Run pipeline steps after cvelistV5 bulk load (when ``store`` is configured).

    :param store: The SQLite store to enrich the NVD for.
    :type store: SqliteCveStore | None
    :param ingestion_ran: True when cvelistV5 ingestion ran this gather. Passed
        to every phase that can otherwise skip on a watermark — KEV (catalog
        version), NVD (``lastModified``) and the exploit phases (corpus
        version) — to suppress the skip (the heal guard): an ingest
        cascade-wipes their rows, which must be restored even when the upstream
        source has not moved. Defaults True (the safe direction: re-parse
        rather than risk a stale ``False``).
    :type ingestion_ran: bool
    :return: None
    :rtype: None
    """
    if store is None:
        return

    logger.info("Running post-ingestion enrichment...")

    if skip_kev:
        logger.info("CISA KEV: skipped (--skip-kev)")
    else:
        logger.info("Ingesting CISA KEV catalog...")
        await ingest_cisa_kev_catalog(store, force=ingestion_ran)

    if skip_nvd:
        logger.info("NVD: skipped (--skip-nvd)")
    else:
        logger.info("Enriching all NVD...")
        await enrich_all_nvd(store, full=ingestion_ran)

    # ⚠️ **Before the vendor index, not after.** This phase moves
    # ``affected_product`` rows off the placeholder product, and the vendor
    # index rolls CPE evidence up *per product_id* — so running it first means
    # the index sees the corrected identities, and the placeholder product it
    # has to exclude by size is that much smaller.
    if skip_placeholder_products:
        logger.info("Placeholder products: skipped (--skip-placeholder-products)")
    else:
        logger.info("Resolving placeholder product names from CPE...")
        await refresh_placeholder_products(store)

    # Straight after NVD: this is a pure rollup of ``affected_product`` ⋈
    # ``cpe_match``, and NVD is the only phase that writes ``cpe_match``.
    if skip_vendor_index:
        logger.info("Vendor index: skipped (--skip-vendor-index)")
    else:
        logger.info("Refreshing product/CPE-vendor index...")
        await refresh_vendor_index(store)

    if skip_epss:
        logger.info("EPSS: skipped (--skip-epss)")
    else:
        logger.info("Enriching all EPSS...")
        await enrich_all_epss(store)

    if skip_osv:
        logger.info("OSV: skipped (--skip-osv)")
    else:
        logger.info("Enriching all OSV...")
        await enrich_all_osv(store)

    if skip_nuclei:
        logger.info("Nuclei: skipped (--skip-nuclei)")
    else:
        logger.info("Ingesting Nuclei exploit templates...")
        await ingest_nuclei_templates(store, ingestion_ran=ingestion_ran)

    if skip_exploitdb:
        logger.info("Exploit-DB: skipped (--skip-exploitdb)")
    else:
        logger.info("Ingesting Exploit-DB entries...")
        await ingest_exploitdb(store, ingestion_ran=ingestion_ran)

    if skip_metasploit:
        logger.info("Metasploit: skipped (--skip-metasploit)")
    else:
        logger.info("Ingesting Metasploit module metadata...")
        await ingest_metasploit(store, ingestion_ran=ingestion_ran)

    # Materialise the tri-state summary bools once, after the exploit phases:
    # the all-contributing-sources rule needs every source's completion visible,
    # and a single full-corpus pass beats one per phase.
    write_back_exploit_bools(store.connection)
    store.connection.commit()

    logger.info("Processing vendor advisories...")
    await process_vendor_advisories(store)


__all__ = [
    "NVD_BULK_COMMIT_EVERY_N_PAGES",
    "NVD_KEYED_REQUEST_DELAY_SEC",
    "NVD_LAST_MOD_WINDOW_DAYS",
    "NVD_PIPELINE_PHASE",
    "NVD_PUBLIC_REQUEST_DELAY_SEC",
    "enrich_all_nvd",
    "run_post_ingestion_enrichment",
]
