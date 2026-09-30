"""Placeholder-product phase: recover product identity from CPE after NVD.

Must run **after** the NVD phase, because it reads ``cpe_match``, and on every
gather rather than from a watermark: ``affected_product`` is cascade-wiped and
rebuilt whenever a CVE is re-ingested, so a resolution made last run is undone
by the next re-parse of the bulk archive. The watermark is recorded for
observability and is never used to short-circuit — the same reasoning, and the
same shape, as :mod:`vulnify.providers.vendor_index`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from vulnify.db.pipeline_state import set_phase_state
from vulnify.db.placeholder_products import resolve_placeholder_products

if TYPE_CHECKING:
    from vulnify.db.sqlite_store import SqliteCveStore

PLACEHOLDER_PRODUCTS_PHASE = "placeholder_products"


async def refresh_placeholder_products(store: SqliteCveStore) -> tuple[int, int]:
    """Repoint placeholder-owned ``affected_product`` rows onto real identities.

    :param store: The SQLite store to refresh.
    :type store: SqliteCveStore
    :return: ``(rows_repointed, cves_resolved)``.
    :rtype: tuple[int, int]
    """
    conn = store.connection
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        moved, cves = resolve_placeholder_products(conn)
        set_phase_state(
            conn,
            PLACEHOLDER_PRODUCTS_PHASE,
            completed_at=now_iso,
            watermark=f"{moved}:{cves}",
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception(
            "placeholder products: resolution failed; rows left on the placeholder"
        )
        raise
    return moved, cves


__all__ = ["PLACEHOLDER_PRODUCTS_PHASE", "refresh_placeholder_products"]
