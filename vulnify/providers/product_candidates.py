"""Product-candidates phase: description-named products for CVEs nothing else identifies.

Runs after ``placeholder_products`` (which decides which CVEs are still
unidentified) and after ``vendor_index`` (whose sentinel repoint gives products
the vendor name the matcher needs), on every gather rather than from a
watermark: the table is derived from ``affected_product``, which re-ingest
cascade-wipes. The watermark is recorded for observability only — same shape as
:mod:`vulnify.providers.placeholder_products`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from vulnify.db.pipeline_state import set_phase_state
from vulnify.db.product_candidates import rebuild_product_candidates

if TYPE_CHECKING:
    from vulnify.db.sqlite_store import SqliteCveStore

PRODUCT_CANDIDATES_PHASE = "product_candidates"


async def refresh_product_candidates(store: SqliteCveStore) -> tuple[int, int]:
    """Rebuild ``product_candidate`` in one transaction.

    :param store: The SQLite store to refresh.
    :type store: SqliteCveStore
    :return: ``(rows_written, cves_with_a_candidate)``.
    :rtype: tuple[int, int]
    """
    conn = store.connection
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        rows, cves = rebuild_product_candidates(conn)
        set_phase_state(
            conn,
            PRODUCT_CANDIDATES_PHASE,
            completed_at=now_iso,
            watermark=f"{rows}:{cves}",
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("product candidates: rebuild failed; previous table kept")
        raise
    return rows, cves


__all__ = ["PRODUCT_CANDIDATES_PHASE", "refresh_product_candidates"]
