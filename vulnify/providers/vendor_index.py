"""Vendor-index phase: refresh the product/CPE-vendor rollup after enrichment.

Must run **after** NVD, because it reads ``cpe_match``, and it must run on every
gather rather than resuming from a watermark: ``affected_product`` and
``cpe_match`` are cascade-wiped and rebuilt whenever a CVE is re-ingested, and
``product_cpe_vendor`` is keyed by ``product_id``. A full rebuild is a few
seconds and is idempotent, so there is nothing to gain from skipping it and a
silently stale vendor index to lose. The watermark is recorded for observability
only — it is never used to short-circuit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from vulnify.db.pipeline_state import set_phase_state
from vulnify.db.vendor_index import build_vendor_index

if TYPE_CHECKING:
    from vulnify.db.sqlite_store import SqliteCveStore

VENDOR_INDEX_PHASE = "vendor_index"


async def refresh_vendor_index(store: SqliteCveStore) -> tuple[int, int]:
    """
    Rebuild ``product_cpe_vendor`` and repoint unambiguous sentinel products.

    :param store: The SQLite store to refresh.
    :type store: SqliteCveStore
    :return: ``(slug_rows, products_repointed)``.
    :rtype: tuple[int, int]
    """
    conn = store.connection
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        rows, moved = build_vendor_index(conn)
        set_phase_state(
            conn,
            VENDOR_INDEX_PHASE,
            completed_at=now_iso,
            watermark=f"{rows}:{moved}",
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("vendor index: refresh failed; index left unchanged")
        raise
    return rows, moved


__all__ = ["VENDOR_INDEX_PHASE", "refresh_vendor_index"]
