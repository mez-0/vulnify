"""CVE ingestion + post-ingestion enrichment CLI (`vulnify-gather`)."""

from __future__ import annotations

import argparse
import asyncio

import vulnify.settings  # noqa: F401 — load `.env` before other vulnify imports
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.providers.cveproject import process_cveproject
from vulnify.providers.enrichment import run_post_ingestion_enrichment
from vulnify.settings import VULNIFY_SQLITE_PATH, get_sqlite_path_from_env


async def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vulnify-gather",
        description="Process the CVEProject and run post-ingestion enrichment.",
    )
    parser.add_argument(
        "-s",
        "--skip-ingestion",
        action="store_true",
        help="Skip the ingestion of the CVEProject.",
    )
    parser.add_argument(
        "--skip-nvd",
        action="store_true",
        help="Skip NVD bulk enrichment (~1h without an API key on the 2026-11 "
        "corpus; a key shortens the inter-page sleep, not the fetch and merge).",
    )
    parser.add_argument(
        "--skip-vendor-index",
        action="store_true",
        help="Skip the product/CPE-vendor index rebuild (~1 min; leaves "
        "vendor lookups stale for products with no cvelistV5 vendor).",
    )
    parser.add_argument(
        "--skip-placeholder-products",
        action="store_true",
        help="Skip recovering product identity for CVEs whose CNA wrote a "
        "placeholder product name (leaves them unreachable by product lookup).",
    )
    parser.add_argument(
        "--skip-osv",
        action="store_true",
        help="Skip OSV enrichment (~3h after an ingest, which wipes the per-CVE "
        "osv_checked markers; incremental on runs without one).",
    )
    parser.add_argument(
        "--skip-kev",
        action="store_true",
        help="Skip CISA KEV catalog ingest.",
    )
    parser.add_argument(
        "--skip-epss",
        action="store_true",
        help="Skip EPSS batch enrichment (~50 min; re-scores every CVE).",
    )
    parser.add_argument(
        "--skip-nuclei",
        action="store_true",
        help="Skip Nuclei exploit-template ingest.",
    )
    parser.add_argument(
        "--skip-exploitdb",
        action="store_true",
        help="Skip Exploit-DB artefact ingest.",
    )
    parser.add_argument(
        "--skip-metasploit",
        action="store_true",
        help="Skip Metasploit module-metadata ingest.",
    )

    args = parser.parse_args()

    db_path = get_sqlite_path_from_env()
    if db_path is None:
        raise RuntimeError(
            f"{VULNIFY_SQLITE_PATH} is unset — set it in .env to point at the "
            "vulnify SQLite DB before running vulnify-gather (see .env.example)."
        )

    if not args.skip_ingestion:
        await process_cveproject(db_path=db_path)

    with SqliteCveStore(db_path) as store:
        await run_post_ingestion_enrichment(
            store,
            skip_kev=args.skip_kev,
            skip_nvd=args.skip_nvd,
            skip_vendor_index=args.skip_vendor_index,
            skip_placeholder_products=args.skip_placeholder_products,
            skip_epss=args.skip_epss,
            skip_osv=args.skip_osv,
            skip_nuclei=args.skip_nuclei,
            skip_exploitdb=args.skip_exploitdb,
            skip_metasploit=args.skip_metasploit,
            ingestion_ran=not args.skip_ingestion,
        )


def run() -> None:
    """Sync entry point for the ``vulnify-gather`` console script."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
