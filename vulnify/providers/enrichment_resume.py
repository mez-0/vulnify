"""Resume long-running enrichments by skipping rows already populated in SQLite."""

from __future__ import annotations

import sqlite3


def cve_ids_pending_nvd(conn: sqlite3.Connection) -> tuple[list[str], int]:
    """
    CVE IDs that still need an NVD 2.0 per-CVE fetch.

    Rows where :func:`~vulnify.providers.nvd.merge_nvd_cve_document` has already
    run have non-empty ``vuln_status`` or ``source_identifier`` (both are set
    from the NVD ``cve`` object).
    """
    total = int(conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0])
    cur = conn.execute(
        """
        SELECT cve_id FROM cve
        WHERE trim(COALESCE(vuln_status, '')) = ''
          AND trim(COALESCE(source_identifier, '')) = ''
        ORDER BY cve_id
        """
    )
    return [str(r[0]) for r in cur.fetchall()], total


def cve_ids_pending_epss(conn: sqlite3.Connection) -> tuple[list[str], int]:
    """
    CVE IDs whose ``intel`` row still looks untouched by EPSS (both scores zero).

    Re-fetches CVEs that may have been omitted from a partial EPSS run. CVEs
    where EPSS genuinely returned zeros for both fields are re-queried each run;
    that case is rare.
    """
    total = int(conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0])
    cur = conn.execute(
        """
        SELECT c.cve_id FROM cve c
        LEFT JOIN intel i ON i.cve_id = c.cve_id
        WHERE COALESCE(i.epss_score, 0) = 0
          AND COALESCE(i.epss_percentile, 0) = 0
        ORDER BY c.cve_id
        """
    )
    return [str(r[0]) for r in cur.fetchall()], total


def cve_ids_pending_osv(conn: sqlite3.Connection) -> tuple[list[str], int]:
    """
    CVE IDs that have not yet been conclusively checked against OSV.

    A CVE is considered done once it carries an ``osv_package`` (a hit) or an
    ``osv_checked`` marker (queried, no packages). The ~99% of CVEs absent from
    OSV are marked checked so they aren't re-queried on every run; only
    genuinely new CVEs remain pending. Transient failures leave no marker, so
    they stay pending and are retried.
    """
    total = int(conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0])
    cur = conn.execute(
        """
        SELECT c.cve_id FROM cve c
        WHERE NOT EXISTS (
            SELECT 1 FROM intel_string_list isl
            WHERE isl.cve_id = c.cve_id
              AND isl.kind IN ('osv_package', 'osv_checked')
        )
        ORDER BY c.cve_id
        """
    )
    return [str(r[0]) for r in cur.fetchall()], total


__all__ = [
    "cve_ids_pending_epss",
    "cve_ids_pending_nvd",
    "cve_ids_pending_osv",
]
