"""Vendor advisories — reserved for curated vendor fix / bulletin ingestion."""

from __future__ import annotations

from loguru import logger
from tqdm import tqdm


async def process_vendor_advisories(_store: object | None = None) -> None:
    """
    Placeholder for pipeline step 7 (ground-truth fixes from vendor bulletins).

    Use CNA / NVD references today; extend here to scrape or ingest advisory feeds
    with explicit patch versions.
    """
    logger.debug("vendor advisories: no external ingest configured (stub)")
    pending: list[object] = []
    for _ in tqdm(pending, desc="Vendor advisories", unit="adv", disable=not pending):
        pass


__all__ = ["process_vendor_advisories"]
