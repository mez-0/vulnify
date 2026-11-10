"""Vendor-index phase: refresh the product and per-CVE CPE-vendor rollups.

Must run **after** NVD, because it reads ``cpe_match``, and it must run on every
gather rather than resuming from a watermark: ``affected_product`` and
``cpe_match`` are cascade-wiped and rebuilt whenever a CVE is re-ingested, and
``product_cpe_vendor`` is keyed by ``product_id``. A full rebuild of both
tables is well under a minute and is idempotent, so there is nothing to gain
from skipping it and a silently stale vendor index to lose. The watermark is
recorded for observability only — it is never used to short-circuit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from vulnify.db.pipeline_state import set_phase_state
from vulnify.db.vendor_index import build_vendor_index, rebuild_cve_cpe_vendor

if TYPE_CHECKING:
    from vulnify.db.sqlite_store import SqliteCveStore

VENDOR_INDEX_PHASE = "vendor_index"


async def refresh_vendor_index(store: SqliteCveStore) -> tuple[int, int]:
    """
    Rebuild ``product_cpe_vendor``, repoint unambiguous sentinel products, then
    rebuild the per-CVE ``cve_cpe_vendor`` edges.

    The watermark is ``product_rows:repointed:cve_edges``.

    :param store: The SQLite store to refresh.
    :type store: SqliteCveStore
    :return: ``(slug_rows, products_repointed)``.
    :rtype: tuple[int, int]
    """
    conn = store.connection
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        rows, moved = build_vendor_index(conn)
        edges = rebuild_cve_cpe_vendor(conn)
        logger.info("vendor index: {edges:,} per-CVE CPE-vendor edges", edges=edges)
        set_phase_state(
            conn,
            VENDOR_INDEX_PHASE,
            completed_at=now_iso,
            watermark=f"{rows}:{moved}:{edges}",
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("vendor index: refresh failed; index left unchanged")
        raise
    return rows, moved


__all__ = ["VENDOR_INDEX_PHASE", "refresh_vendor_index"]
