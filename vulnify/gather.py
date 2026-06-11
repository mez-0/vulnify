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
        help="Skip NVD bulk enrichment (~30 min without an API key, ~3 min with one).",
    )
    parser.add_argument(
        "--skip-osv",
        action="store_true",
        help="Skip OSV enrichment (concurrent backfill, <1h; incremental after).",
    )
    parser.add_argument(
        "--skip-kev",
        action="store_true",
        help="Skip CISA KEV catalog ingest.",
    )
    parser.add_argument(
        "--skip-epss",
        action="store_true",
        help="Skip EPSS batch enrichment.",
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
