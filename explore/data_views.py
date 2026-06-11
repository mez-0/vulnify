"""Extended SQLite accessors powering the v2 visual tabs.

Loaders here follow the same pattern as :mod:`explore.data`:
``@st.cache_data(ttl=60, show_spinner=False)`` on top of a read-only
``connect_readonly`` connection wrapped in ``try/finally``. Every loader takes
``db_path_str`` (cache key), most also accept the published-date filter pair
``(date_min, date_max)`` so they slot into the existing sidebar without
rewiring.
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from explore.data import _NAMED_VENDOR_PREDICATE, _date_clause, connect_readonly

# ============================================================
# Severity helpers (max CVSS score per CVE → bucket)
# ============================================================

# Order used everywhere severity appears as a categorical axis.
SEVERITY_ORDER: tuple[str, ...] = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "NONE",
    "UNKNOWN",
)

# Plotly colour map keyed on the bucket name.
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#7c241b",
    "HIGH": "#c0392b",
    "MEDIUM": "#e67e22",
    "LOW": "#27ae60",
    "NONE": "#7f8c8d",
    "UNKNOWN": "#34495e",
}

# Inline SQL CASE for severity bucketing — assumes the outer query exposes
# ``mx.s`` as the per-CVE max ``cvss.score``.
_SEVERITY_CASE_SQL = """
CASE
    WHEN mx.s IS NULL THEN 'UNKNOWN'
    WHEN mx.s >= 9.0 THEN 'CRITICAL'
    WHEN mx.s >= 7.0 THEN 'HIGH'
    WHEN mx.s >= 4.0 THEN 'MEDIUM'
    WHEN mx.s > 0.0 THEN 'LOW'
    ELSE 'NONE'
END
"""


# ============================================================
# Overview upgrades + pipeline health
# ============================================================


@st.cache_data(ttl=600, show_spinner=False)
def load_pipeline_run(db_path_str: str) -> pd.DataFrame:
    """
    Read the ``pipeline_run`` resume table (per-phase last completion + watermark).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :return: One row per phase, sorted alphabetically.
    :rtype: pd.DataFrame
    """
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            """
            SELECT phase, last_completed_at, last_watermark
            FROM pipeline_run
            ORDER BY phase
            """,
            conn,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_enrichment_coverage(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Per-enrichment coverage of the filtered CVE window.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published`` (inclusive ``YYYY-MM-DD``).
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published`` (inclusive ``YYYY-MM-DD``).
    :type date_max: str | None
    :return: ``(enrichment, present, total, share)`` rows.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        cur = conn.cursor()
        total = cur.execute(
            f"SELECT COUNT(*) FROM cve c WHERE {clause}", params
        ).fetchone()[0]
        if total == 0:
            return pd.DataFrame(columns=["enrichment", "present", "total", "share"])

        spec: list[tuple[str, str]] = [
            (
                "CVSS",
                f"SELECT COUNT(DISTINCT c.cve_id) FROM cve c "
                f"JOIN cvss x ON x.cve_id = c.cve_id WHERE {clause}",
            ),
            (
                "EPSS",
                f"SELECT COUNT(*) FROM cve c "
                f"JOIN intel i ON i.cve_id = c.cve_id "
                f"WHERE {clause} AND i.epss_score IS NOT NULL",
            ),
            (
                "KEV listed",
                f"SELECT COUNT(*) FROM cve c "
                f"JOIN kev k ON k.cve_id = c.cve_id "
                f"WHERE {clause} AND k.listed = 1",
            ),
            (
                "CWE",
                f"SELECT COUNT(DISTINCT c.cve_id) FROM cve c "
                f"JOIN cve_cwe cw ON cw.cve_id = c.cve_id WHERE {clause}",
            ),
            (
                "Exploit in-the-wild",
                f"SELECT COUNT(*) FROM cve c "
                f"JOIN exploit e ON e.cve_id = c.cve_id "
                f"WHERE {clause} AND e.in_the_wild = 1",
            ),
            (
                "References",
                f"SELECT COUNT(DISTINCT c.cve_id) FROM cve c "
                f"JOIN reference r ON r.cve_id = c.cve_id WHERE {clause}",
            ),
            (
                "Affected products",
                f"SELECT COUNT(DISTINCT c.cve_id) FROM cve c "
                f"JOIN affected_product a ON a.cve_id = c.cve_id WHERE {clause}",
            ),
            (
                "CPE matches",
                f"SELECT COUNT(DISTINCT c.cve_id) FROM cve c "
                f"JOIN cpe_match m ON m.cve_id = c.cve_id WHERE {clause}",
            ),
        ]
        rows: list[tuple[str, int, int, float]] = []
        for label, sql in spec:
            n = cur.execute(sql, params).fetchone()[0]
            rows.append((label, int(n), int(total), float(n) / total if total else 0.0))
        return pd.DataFrame(rows, columns=["enrichment", "present", "total", "share"])
    finally:
        conn.close()


@st.cache_data(ttl=600, show_spinner=False)
def load_table_row_counts(db_path_str: str) -> pd.DataFrame:
    """
    Row counts for the major tables (operational view, no date filter).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :return: ``(table, n_rows)`` sorted DESC.
    :rtype: pd.DataFrame
    """
    tables = [
        "cve",
        "cvss",
        "cwe",
        "cve_cwe",
        "vendor",
        "cve_vendor",
        "product",
        "affected_product",
        "version_range",
        "intel",
        "intel_string_list",
        "kev",
        "exploit",
        "reference",
        "reference_tag",
        "tag",
        "cve_tag",
        "cpe_match",
        "pipeline_run",
    ]
    conn = connect_readonly(db_path_str)
    try:
        rows: list[tuple[str, int]] = []
        for t in tables:
            n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            rows.append((t, int(n)))
        return (
            pd.DataFrame(rows, columns=["table", "n_rows"])
            .sort_values("n_rows", ascending=False)
            .reset_index(drop=True)
        )
    finally:
        conn.close()


@st.cache_data(ttl=600, show_spinner=False)
def load_distinct_dimension_counts(db_path_str: str) -> dict[str, int]:
    """
    Distinct counts of the headline dimensions.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :return: Mapping with ``vendors``, ``products``, ``cwes``, ``tags``,
        ``cnas``, ``kev_listed``.
    :rtype: dict[str, int]
    """
    conn = connect_readonly(db_path_str)
    try:
        cur = conn.cursor()
        return {
            "vendors": cur.execute(
                "SELECT COUNT(*) FROM vendor WHERE trim(coalesce(name,'')) <> ''"
            ).fetchone()[0],
            "products": cur.execute("SELECT COUNT(*) FROM product").fetchone()[0],
            "cwes": cur.execute("SELECT COUNT(*) FROM cwe").fetchone()[0],
            "tags": cur.execute("SELECT COUNT(*) FROM tag").fetchone()[0],
            "cnas": cur.execute(
                "SELECT COUNT(DISTINCT trim(cna)) FROM cve "
                "WHERE trim(coalesce(cna,'')) <> ''"
            ).fetchone()[0],
            "kev_listed": cur.execute(
                "SELECT COUNT(*) FROM kev WHERE listed = 1"
            ).fetchone()[0],
        }
    finally:
        conn.close()


# ============================================================
# Trends upgrades — severity stack, YoY, weekly
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_severity_monthly(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Monthly CVE counts bucketed by severity (max CVSS per CVE).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(ym, severity, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y-%m', c.published) AS ym,
                   {_SEVERITY_CASE_SQL} AS severity,
                   COUNT(*) AS n
            FROM cve c
            LEFT JOIN (
                SELECT cve_id, MAX(score) AS s FROM cvss GROUP BY cve_id
            ) mx ON mx.cve_id = c.cve_id
            WHERE {clause}
            GROUP BY ym, severity
            ORDER BY ym, severity
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_publications_yoy(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Year-over-year CVE counts pivoted on month-of-year.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(year, month, n)`` rows; month is 1–12.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT CAST(strftime('%Y', c.published) AS INTEGER) AS year,
                   CAST(strftime('%m', c.published) AS INTEGER) AS month,
                   COUNT(*) AS n
            FROM cve c
            WHERE {clause}
            GROUP BY year, month
            ORDER BY year, month
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_publications_weekly(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Weekly CVE counts (ISO-style week label).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(yw, n)`` ordered by ``yw``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y-%W', c.published) AS yw, COUNT(*) AS n
            FROM cve c
            WHERE {clause}
            GROUP BY yw
            ORDER BY yw
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


# ============================================================
# Severity & CWE upgrades
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_severity_distribution(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Severity bucket counts (max CVSS per CVE).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(severity, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT {_SEVERITY_CASE_SQL} AS severity, COUNT(*) AS n
            FROM cve c
            LEFT JOIN (
                SELECT cve_id, MAX(score) AS s FROM cvss GROUP BY cve_id
            ) mx ON mx.cve_id = c.cve_id
            WHERE {clause}
            GROUP BY severity
            ORDER BY n DESC
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cvss_subscore_sample(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    sample_limit: int = 5000,
) -> pd.DataFrame:
    """
    Random sample of CVSS subscores with severity bucket.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param sample_limit: Maximum rows to fetch.
    :type sample_limit: int
    :return: ``(cve_id, exploitability_score, impact_score, score, severity)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT x.cve_id,
                   x.exploitability_score,
                   x.impact_score,
                   x.score,
                   CASE
                       WHEN x.score IS NULL THEN 'UNKNOWN'
                       WHEN x.score >= 9.0 THEN 'CRITICAL'
                       WHEN x.score >= 7.0 THEN 'HIGH'
                       WHEN x.score >= 4.0 THEN 'MEDIUM'
                       WHEN x.score > 0.0 THEN 'LOW'
                       ELSE 'NONE'
                   END AS severity
            FROM cvss x
            JOIN cve c ON c.cve_id = x.cve_id
            WHERE {clause}
              AND x.exploitability_score IS NOT NULL
              AND x.impact_score IS NOT NULL
            ORDER BY RANDOM()
            LIMIT ?
            """,
            conn,
            params=[*params, sample_limit],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cwe_severity_heatmap(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_m: int,
) -> pd.DataFrame:
    """
    Top-N CWE × severity bucket counts.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param top_m: Number of top CWEs to include.
    :type top_m: int
    :return: ``(cwe_id, cwe_name, severity, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            WITH top_cwe AS (
                SELECT cc.cwe_id
                FROM cve_cwe cc
                JOIN cve c ON c.cve_id = cc.cve_id
                WHERE {clause}
                GROUP BY cc.cwe_id
                ORDER BY COUNT(*) DESC
                LIMIT ?
            )
            SELECT cc.cwe_id,
                   cw.name AS cwe_name,
                   {_SEVERITY_CASE_SQL} AS severity,
                   COUNT(*) AS n
            FROM cve_cwe cc
            JOIN top_cwe tc ON tc.cwe_id = cc.cwe_id
            JOIN cwe cw ON cw.cwe_id = cc.cwe_id
            JOIN cve c ON c.cve_id = cc.cve_id
            LEFT JOIN (
                SELECT cve_id, MAX(score) AS s FROM cvss GROUP BY cve_id
            ) mx ON mx.cve_id = cc.cve_id
            WHERE {clause}
            GROUP BY cc.cwe_id, severity
            ORDER BY cc.cwe_id, severity
            """,
            conn,
            params=[*params, top_m, *params],
        )
    finally:
        conn.close()


# ============================================================
# Enrichment upgrades — EPSS by severity, density, KEV decile
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_epss_by_severity(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    sample_limit: int = 12000,
) -> pd.DataFrame:
    """
    Random sample of ``(severity, epss_score)`` pairs.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param sample_limit: Maximum rows to fetch.
    :type sample_limit: int
    :return: ``(severity, epss_score)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT {_SEVERITY_CASE_SQL} AS severity, i.epss_score
            FROM intel i
            JOIN cve c ON c.cve_id = i.cve_id
            LEFT JOIN (
                SELECT cve_id, MAX(score) AS s FROM cvss GROUP BY cve_id
            ) mx ON mx.cve_id = i.cve_id
            WHERE {clause}
              AND i.epss_score IS NOT NULL
            ORDER BY RANDOM()
            LIMIT ?
            """,
            conn,
            params=[*params, sample_limit],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_epss_density(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    pct_bins: int = 20,
    cvss_bins: int = 11,
) -> pd.DataFrame:
    """
    Pre-binned 2-D counts of ``epss_percentile × max-CVSS``.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param pct_bins: Number of EPSS-percentile bins (0–100 split evenly).
    :type pct_bins: int
    :param cvss_bins: Number of CVSS bins (0–10 split evenly).
    :type cvss_bins: int
    :return: ``(pct_bin, cvss_bin, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        df = pd.read_sql_query(
            f"""
            SELECT i.epss_percentile, mx.s AS cvss_max
            FROM intel i
            JOIN cve c ON c.cve_id = i.cve_id
            LEFT JOIN (
                SELECT cve_id, MAX(score) AS s FROM cvss GROUP BY cve_id
            ) mx ON mx.cve_id = i.cve_id
            WHERE {clause}
              AND i.epss_percentile IS NOT NULL
              AND mx.s IS NOT NULL
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()

    if df.empty:
        return pd.DataFrame(columns=["pct_bin", "cvss_bin", "n"])

    pct_edges = pd.cut(df["epss_percentile"], bins=pct_bins, include_lowest=True)
    cvss_edges = pd.cut(df["cvss_max"], bins=cvss_bins, include_lowest=True)
    grouped = (
        df.assign(pct_bin=pct_edges.astype(str), cvss_bin=cvss_edges.astype(str))
        .groupby(["pct_bin", "cvss_bin"], observed=True)
        .size()
        .reset_index(name="n")
    )
    return grouped


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_share_by_epss_decile(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    KEV-listed share within each EPSS-percentile decile.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(decile, n_total, n_kev, kev_share)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT CASE
                       WHEN i.epss_percentile >= 1.0 THEN 9
                       WHEN i.epss_percentile < 0 THEN 0
                       ELSE CAST(i.epss_percentile * 10 AS INTEGER)
                   END AS decile,
                   COUNT(*) AS n_total,
                   SUM(CASE WHEN k.listed = 1 THEN 1 ELSE 0 END) AS n_kev,
                   AVG(CASE WHEN k.listed = 1 THEN 1.0 ELSE 0.0 END) AS kev_share
            FROM intel i
            JOIN cve c ON c.cve_id = i.cve_id
            LEFT JOIN kev k ON k.cve_id = i.cve_id
            WHERE {clause}
              AND i.epss_percentile IS NOT NULL
            GROUP BY decile
            ORDER BY decile
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


# ============================================================
# Exploit landscape
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_exploit_maturity_dist(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Distribution of ``exploit.maturity`` across the filtered CVE window.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(maturity, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT COALESCE(NULLIF(trim(e.maturity),''),'NONE') AS maturity,
                   COUNT(*) AS n
            FROM exploit e
            JOIN cve c ON c.cve_id = e.cve_id
            WHERE {clause}
            GROUP BY maturity
            ORDER BY n DESC
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_exploit_flag_totals(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> dict[str, int]:
    """
    Counts of CVEs with each exploit flag set (in the filtered window).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: Mapping of flag name to count.
    :rtype: dict[str, int]
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        row = conn.execute(
            f"""
            SELECT
                SUM(CASE WHEN e.public_poc = 1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN e.metasploit = 1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN e.ransomware_usage = 1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN e.in_the_wild = 1 THEN 1 ELSE 0 END),
                COUNT(*)
            FROM exploit e
            JOIN cve c ON c.cve_id = e.cve_id
            WHERE {clause}
            """,
            params,
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return {"public_poc": 0, "metasploit": 0, "ransomware": 0, "in_the_wild": 0, "total": 0}
    return {
        "public_poc": int(row[0] or 0),
        "metasploit": int(row[1] or 0),
        "ransomware": int(row[2] or 0),
        "in_the_wild": int(row[3] or 0),
        "total": int(row[4] or 0),
    }


@st.cache_data(ttl=60, show_spinner=False)
def load_exploit_artefact_totals(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> dict[str, int]:
    """
    Headline counts for the ``exploit_artefact`` evidence layer (in the window).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``total`` artefacts, ``distinct_cves`` covered, and per-source counts.
    :rtype: dict[str, int]
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        row = conn.execute(
            f"""
            SELECT
                COUNT(*),
                COUNT(DISTINCT a.cve_id),
                SUM(CASE WHEN a.source = 'nuclei' THEN 1 ELSE 0 END),
                SUM(CASE WHEN a.source = 'exploitdb' THEN 1 ELSE 0 END),
                SUM(CASE WHEN a.source = 'metasploit' THEN 1 ELSE 0 END)
            FROM exploit_artefact a
            JOIN cve c ON c.cve_id = a.cve_id
            WHERE {clause}
            """,
            params,
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return {
            "total": 0,
            "distinct_cves": 0,
            "nuclei": 0,
            "exploitdb": 0,
            "metasploit": 0,
        }
    return {
        "total": int(row[0] or 0),
        "distinct_cves": int(row[1] or 0),
        "nuclei": int(row[2] or 0),
        "exploitdb": int(row[3] or 0),
        "metasploit": int(row[4] or 0),
    }


@st.cache_data(ttl=60, show_spinner=False)
def load_exploit_artefact_source_breakdown(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Artefact counts split by source and provenance confidence.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(source, confidence, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT a.source AS source, a.confidence AS confidence, COUNT(*) AS n
            FROM exploit_artefact a
            JOIN cve c ON c.cve_id = a.cve_id
            WHERE {clause}
            GROUP BY a.source, a.confidence
            ORDER BY n DESC
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_top_artefact_cves(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    limit: int = 20,
) -> pd.DataFrame:
    """
    CVEs carrying the most exploit artefacts (a rough "best-evidenced" list).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param limit: Max rows.
    :type limit: int
    :return: ``(cve_id, title, artefacts, sources)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT a.cve_id AS cve_id,
                   c.title AS title,
                   COUNT(*) AS artefacts,
                   COUNT(DISTINCT a.source) AS sources
            FROM exploit_artefact a
            JOIN cve c ON c.cve_id = a.cve_id
            WHERE {clause}
            GROUP BY a.cve_id, c.title
            ORDER BY artefacts DESC, a.cve_id
            LIMIT ?
            """,
            conn,
            params=[*params, int(limit)],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_exploit_in_the_wild_monthly(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Monthly count of CVEs flagged as exploited in the wild.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(ym, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y-%m', c.published) AS ym, COUNT(*) AS n
            FROM exploit e
            JOIN cve c ON c.cve_id = e.cve_id
            WHERE e.in_the_wild = 1 AND {clause}
            GROUP BY ym
            ORDER BY ym
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_exploit_vs_cvss(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    sample_limit: int = 8000,
) -> pd.DataFrame:
    """
    Sampled ``(in_the_wild, max-CVSS)`` rows for box-plot comparisons.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param sample_limit: Maximum rows from the non-ITW pool.
    :type sample_limit: int
    :return: ``(group, cvss_max)`` where group ∈ {"in_the_wild", "other"}.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        in_wild = pd.read_sql_query(
            f"""
            SELECT 'in_the_wild' AS grp, mx.s AS cvss_max
            FROM exploit e
            JOIN cve c ON c.cve_id = e.cve_id
            JOIN (
                SELECT cve_id, MAX(score) AS s FROM cvss GROUP BY cve_id
            ) mx ON mx.cve_id = e.cve_id
            WHERE e.in_the_wild = 1 AND {clause}
            """,
            conn,
            params=params,
        )
        other = pd.read_sql_query(
            f"""
            SELECT 'other' AS grp, mx.s AS cvss_max
            FROM exploit e
            JOIN cve c ON c.cve_id = e.cve_id
            JOIN (
                SELECT cve_id, MAX(score) AS s FROM cvss GROUP BY cve_id
            ) mx ON mx.cve_id = e.cve_id
            WHERE e.in_the_wild = 0 AND {clause}
            ORDER BY RANDOM()
            LIMIT ?
            """,
            conn,
            params=[*params, sample_limit],
        )
    finally:
        conn.close()
    return pd.concat([in_wild, other], ignore_index=True)


@st.cache_data(ttl=60, show_spinner=False)
def load_vendor_itw_pressure(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_n: int,
    min_cves: int = 25,
) -> pd.DataFrame:
    """
    Vendors ranked by share of CVEs flagged as exploited in the wild.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param top_n: Maximum vendors to return.
    :type top_n: int
    :param min_cves: Drop vendors with fewer total CVEs (avoids 1/1 = 100%).
    :type min_cves: int
    :return: ``(vendor_name, n_total, n_itw, share)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT v.name AS vendor_name,
                   COUNT(DISTINCT cv.cve_id) AS n_total,
                   SUM(CASE WHEN e.in_the_wild = 1 THEN 1 ELSE 0 END) AS n_itw,
                   1.0 * SUM(CASE WHEN e.in_the_wild = 1 THEN 1 ELSE 0 END)
                       / NULLIF(COUNT(DISTINCT cv.cve_id), 0) AS share
            FROM cve_vendor cv
            JOIN vendor v ON v.vendor_id = cv.vendor_id
            JOIN cve c ON c.cve_id = cv.cve_id
            LEFT JOIN exploit e ON e.cve_id = cv.cve_id
            WHERE {clause}
              AND {_NAMED_VENDOR_PREDICATE}
            GROUP BY v.vendor_id
            HAVING n_total >= ?
            ORDER BY share DESC, n_total DESC
            LIMIT ?
            """,
            conn,
            params=[*params, min_cves, top_n],
        )
    finally:
        conn.close()


# ============================================================
# KEV deep dive
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_source_split(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    KEV row counts grouped by ``source`` (``cisa``, ``nvd``, blank).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(source, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT COALESCE(NULLIF(trim(k.source),''),'(unset)') AS source,
                   COUNT(*) AS n
            FROM kev k
            JOIN cve c ON c.cve_id = k.cve_id
            WHERE k.listed = 1 AND {clause}
            GROUP BY source
            ORDER BY n DESC
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_top_vendor_project(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_n: int,
) -> pd.DataFrame:
    """
    Top ``vendor_project`` strings in CISA's KEV catalog.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param top_n: Number of vendors to return.
    :type top_n: int
    :return: ``(vendor_project, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT trim(k.vendor_project) AS vendor_project, COUNT(*) AS n
            FROM kev k
            JOIN cve c ON c.cve_id = k.cve_id
            WHERE k.listed = 1
              AND trim(coalesce(k.vendor_project,'')) <> ''
              AND {clause}
            GROUP BY vendor_project
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_n],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_top_product_label(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_n: int,
) -> pd.DataFrame:
    """
    Top ``product_label`` strings in CISA's KEV catalog.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param top_n: Number of products to return.
    :type top_n: int
    :return: ``(product_label, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT trim(k.product_label) AS product_label, COUNT(*) AS n
            FROM kev k
            JOIN cve c ON c.cve_id = k.cve_id
            WHERE k.listed = 1
              AND trim(coalesce(k.product_label,'')) <> ''
              AND {clause}
            GROUP BY product_label
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_n],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_due_date_buckets(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    today: str,
) -> pd.DataFrame:
    """
    KEV remediation buckets relative to ``today``.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param today: Reference date (``YYYY-MM-DD``).
    :type today: str
    :return: ``(bucket, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        df = pd.read_sql_query(
            f"""
            SELECT
                CASE
                    WHEN trim(coalesce(k.due_date,'')) = '' THEN 'No due date'
                    WHEN substr(trim(k.due_date),1,10) < ? THEN 'Overdue'
                    WHEN CAST(julianday(substr(trim(k.due_date),1,10)) - julianday(?) AS INTEGER) <= 30 THEN 'Due ≤ 30d'
                    WHEN CAST(julianday(substr(trim(k.due_date),1,10)) - julianday(?) AS INTEGER) <= 90 THEN 'Due ≤ 90d'
                    ELSE 'Due > 90d'
                END AS bucket,
                COUNT(*) AS n
            FROM kev k
            JOIN cve c ON c.cve_id = k.cve_id
            WHERE k.listed = 1 AND {clause}
            GROUP BY bucket
            """,
            conn,
            params=[today, today, today, *params],
        )
    finally:
        conn.close()
    bucket_order = ["Overdue", "Due ≤ 30d", "Due ≤ 90d", "Due > 90d", "No due date"]
    df["bucket"] = pd.Categorical(df["bucket"], categories=bucket_order, ordered=True)
    return df.sort_values("bucket").reset_index(drop=True)


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_remediation_span(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.Series:
    """
    Days CISA gives between ``date_added`` and ``due_date`` per KEV.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: Series of integer days.
    :rtype: pd.Series
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        rows = conn.execute(
            f"""
            SELECT CAST(
                       julianday(substr(trim(k.due_date),1,10))
                       - julianday(substr(trim(k.date_added),1,10))
                   AS INTEGER) AS span
            FROM kev k
            JOIN cve c ON c.cve_id = k.cve_id
            WHERE k.listed = 1
              AND trim(coalesce(k.date_added,'')) <> ''
              AND trim(coalesce(k.due_date,'')) <> ''
              AND {clause}
            """,
            params,
        ).fetchall()
    finally:
        conn.close()
    return pd.Series([r[0] for r in rows if r[0] is not None], dtype="float64", name="span_days")


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_required_action_top(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_n: int,
) -> pd.DataFrame:
    """
    Top distinct ``required_action`` phrases verbatim from CISA's catalog.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param top_n: Maximum phrases to return.
    :type top_n: int
    :return: ``(required_action, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT trim(k.required_action) AS required_action, COUNT(*) AS n
            FROM kev k
            JOIN cve c ON c.cve_id = k.cve_id
            WHERE k.listed = 1
              AND trim(coalesce(k.required_action,'')) <> ''
              AND {clause}
            GROUP BY required_action
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_n],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_severity_mix(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Severity mix split by KEV-listed status (for back-to-back compare).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(group, severity, n)`` where group ∈ {"KEV", "non-KEV"}.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT
                CASE WHEN k.listed = 1 THEN 'KEV' ELSE 'non-KEV' END AS grp,
                {_SEVERITY_CASE_SQL} AS severity,
                COUNT(*) AS n
            FROM cve c
            LEFT JOIN kev k ON k.cve_id = c.cve_id
            LEFT JOIN (
                SELECT cve_id, MAX(score) AS s FROM cvss GROUP BY cve_id
            ) mx ON mx.cve_id = c.cve_id
            WHERE {clause}
            GROUP BY grp, severity
            ORDER BY grp, severity
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


# ============================================================
# CVSS vector anatomy
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_cvss_axis_dist(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Distribution of every CVSS vector axis (AV, AC, PR, UI, scope, C/I/A).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(axis, value, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    axes = [
        ("attack_vector", "AV"),
        ("attack_complexity", "AC"),
        ("privileges_required", "PR"),
        ("user_interaction", "UI"),
        ("scope", "Scope"),
        ("confidentiality", "Confidentiality"),
        ("integrity", "Integrity"),
        ("availability", "Availability"),
    ]
    conn = connect_readonly(db_path_str)
    try:
        rows: list[pd.DataFrame] = []
        for col, label in axes:
            rows.append(
                pd.read_sql_query(
                    f"""
                    SELECT ? AS axis,
                           COALESCE(NULLIF(trim(x.{col}),''),'(unset)') AS value,
                           COUNT(*) AS n
                    FROM cvss x
                    JOIN cve c ON c.cve_id = x.cve_id
                    WHERE {clause}
                    GROUP BY value
                    """,
                    conn,
                    params=[label, *params],
                )
            )
        return pd.concat(rows, ignore_index=True)
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cvss_av_pr_heatmap(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Counts grouped by ``attack_vector × privileges_required``.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(av, pr, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT COALESCE(NULLIF(trim(x.attack_vector),''),'(unset)') AS av,
                   COALESCE(NULLIF(trim(x.privileges_required),''),'(unset)') AS pr,
                   COUNT(*) AS n
            FROM cvss x
            JOIN cve c ON c.cve_id = x.cve_id
            WHERE {clause}
            GROUP BY av, pr
            ORDER BY av, pr
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cvss_remote_unauth_funnel(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Stage counts for the remote-unauth-critical funnel.

    Each stage is the count of distinct CVEs that have **at least one** CVSS
    row meeting the cumulative criteria.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(stage, n)`` ordered as listed.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)

    stages: list[tuple[str, str]] = [
        (
            "All CVEs",
            f"SELECT COUNT(*) FROM cve c WHERE {clause}",
        ),
        (
            "Has CVSS",
            f"SELECT COUNT(DISTINCT c.cve_id) FROM cve c JOIN cvss x ON x.cve_id=c.cve_id WHERE {clause}",
        ),
        (
            "AV = NETWORK",
            f"""SELECT COUNT(DISTINCT c.cve_id) FROM cve c
                JOIN cvss x ON x.cve_id=c.cve_id
                WHERE {clause} AND x.attack_vector = 'NETWORK'""",
        ),
        (
            "+ PR = NONE",
            f"""SELECT COUNT(DISTINCT c.cve_id) FROM cve c
                JOIN cvss x ON x.cve_id=c.cve_id
                WHERE {clause} AND x.attack_vector='NETWORK' AND x.privileges_required='NONE'""",
        ),
        (
            "+ UI = NONE",
            f"""SELECT COUNT(DISTINCT c.cve_id) FROM cve c
                JOIN cvss x ON x.cve_id=c.cve_id
                WHERE {clause} AND x.attack_vector='NETWORK' AND x.privileges_required='NONE'
                  AND x.user_interaction='NONE'""",
        ),
        (
            "+ Critical (≥9)",
            f"""SELECT COUNT(DISTINCT c.cve_id) FROM cve c
                JOIN cvss x ON x.cve_id=c.cve_id
                WHERE {clause} AND x.attack_vector='NETWORK' AND x.privileges_required='NONE'
                  AND x.user_interaction='NONE' AND x.score >= 9.0""",
        ),
    ]

    conn = connect_readonly(db_path_str)
    try:
        rows: list[tuple[str, int]] = []
        for label, sql in stages:
            n = conn.execute(sql, params).fetchone()[0]
            rows.append((label, int(n)))
    finally:
        conn.close()
    return pd.DataFrame(rows, columns=["stage", "n"])


# ============================================================
# Products & CPEs
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_top_products(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_n: int,
) -> pd.DataFrame:
    """
    Top products by distinct CVE count.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param top_n: Maximum products to return.
    :type top_n: int
    :return: ``(vendor_name, product_name, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT v.name AS vendor_name,
                   p.name AS product_name,
                   COUNT(DISTINCT a.cve_id) AS n
            FROM affected_product a
            JOIN product p ON p.product_id = a.product_id
            JOIN vendor v ON v.vendor_id = p.vendor_id
            JOIN cve c ON c.cve_id = a.cve_id
            WHERE {clause}
              AND trim(coalesce(p.name,'')) <> ''
              AND trim(coalesce(v.name,'')) <> ''
            GROUP BY v.vendor_id, p.product_id
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_n],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_product_type_dist(db_path_str: str) -> pd.DataFrame:
    """
    Distribution of ``product.product_type`` values.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :return: ``(product_type, n)``.
    :rtype: pd.DataFrame
    """
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            """
            SELECT COALESCE(NULLIF(trim(product_type),''),'UNKNOWN') AS product_type,
                   COUNT(*) AS n
            FROM product
            GROUP BY product_type
            ORDER BY n DESC
            """,
            conn,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cpe_per_cve_hist(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Per-CVE CPE-match count distribution (pre-binned).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(matches, cves)`` rows.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT n AS matches, COUNT(*) AS cves
            FROM (
                SELECT m.cve_id, COUNT(*) AS n
                FROM cpe_match m
                JOIN cve c ON c.cve_id = m.cve_id
                WHERE {clause}
                GROUP BY m.cve_id
            )
            GROUP BY n
            ORDER BY n
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_top_vendors_by_product_count(
    db_path_str: str, top_n: int
) -> pd.DataFrame:
    """
    Vendors ranked by distinct product count.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param top_n: Maximum vendors to return.
    :type top_n: int
    :return: ``(vendor_name, n_products)``.
    :rtype: pd.DataFrame
    """
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT v.name AS vendor_name, COUNT(DISTINCT p.product_id) AS n_products
            FROM product p
            JOIN vendor v ON v.vendor_id = p.vendor_id
            WHERE {_NAMED_VENDOR_PREDICATE.replace('v.name','v.name')}
            GROUP BY v.vendor_id
            ORDER BY n_products DESC
            LIMIT ?
            """,
            conn,
            params=[top_n],
        )
    finally:
        conn.close()


@st.cache_data(ttl=600, show_spinner=False)
def load_version_range_coverage(db_path_str: str) -> dict[str, int]:
    """
    Affected-product rows that have ≥1 ``version_range`` child.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :return: Mapping with ``ap_total``, ``ap_with_vr``, ``ap_without_vr``.
    :rtype: dict[str, int]
    """
    conn = connect_readonly(db_path_str)
    try:
        cur = conn.cursor()
        ap_total = cur.execute("SELECT COUNT(*) FROM affected_product").fetchone()[0]
        ap_with_vr = cur.execute(
            "SELECT COUNT(DISTINCT affected_product_id) FROM version_range"
        ).fetchone()[0]
        return {
            "ap_total": int(ap_total),
            "ap_with_vr": int(ap_with_vr),
            "ap_without_vr": int(ap_total - ap_with_vr),
        }
    finally:
        conn.close()


# ============================================================
# References & sources
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_refs_per_cve_hist(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Per-CVE references-count distribution (pre-binned).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(refs, cves)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT n AS refs, COUNT(*) AS cves
            FROM (
                SELECT r.cve_id, COUNT(*) AS n
                FROM reference r
                JOIN cve c ON c.cve_id = r.cve_id
                WHERE {clause}
                GROUP BY r.cve_id
            )
            GROUP BY n
            ORDER BY n
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_top_ref_sources(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_n: int,
) -> pd.DataFrame:
    """
    Top reference ``source`` values.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param top_n: Maximum sources to return.
    :type top_n: int
    :return: ``(source, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT COALESCE(NULLIF(trim(r.source),''),'(unset)') AS source,
                   COUNT(*) AS n
            FROM reference r
            JOIN cve c ON c.cve_id = r.cve_id
            WHERE {clause}
            GROUP BY source
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_n],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_ref_trust_dist(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Reference ``trust`` tier distribution.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(trust, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT COALESCE(NULLIF(trim(r.trust),''),'(unset)') AS trust,
                   COUNT(*) AS n
            FROM reference r
            JOIN cve c ON c.cve_id = r.cve_id
            WHERE {clause}
            GROUP BY trust
            ORDER BY n DESC
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_ref_tag_dist(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_n: int,
) -> pd.DataFrame:
    """
    Top reference-tag values via ``reference_tag`` join.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param top_n: Maximum tags to return.
    :type top_n: int
    :return: ``(tag, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT trim(rt.tag) AS tag, COUNT(*) AS n
            FROM reference_tag rt
            JOIN reference r ON r.id = rt.reference_id
            JOIN cve c ON c.cve_id = r.cve_id
            WHERE trim(coalesce(rt.tag,'')) <> ''
              AND {clause}
            GROUP BY tag
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_n],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_tag_coverage_yearly(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    tags: tuple[str, ...],
) -> pd.DataFrame:
    """
    Per-year coverage: CVEs that have at least one reference tagged in ``tags``.

    Reference-tag taxonomy is messy (``vendor-advisory``, ``exploit``,
    ``patch``, ``mitigation``, etc.); the caller supplies the tags they want
    treated as one bucket.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param tags: Tag values to match (case-sensitive).
    :type tags: tuple[str, ...]
    :return: ``(year, n_total, n_tagged, share)``.
    :rtype: pd.DataFrame
    """
    if not tags:
        return pd.DataFrame(columns=["year", "n_total", "n_tagged", "share"])
    clause, params = _date_clause("c", date_min, date_max)
    placeholders = ",".join(["?"] * len(tags))
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            WITH tagged AS (
                SELECT DISTINCT r.cve_id
                FROM reference r
                JOIN reference_tag rt ON rt.reference_id = r.id
                WHERE trim(rt.tag) IN ({placeholders})
            )
            SELECT strftime('%Y', c.published) AS year,
                   COUNT(*) AS n_total,
                   SUM(CASE WHEN t.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS n_tagged,
                   1.0 * SUM(CASE WHEN t.cve_id IS NOT NULL THEN 1 ELSE 0 END)
                       / NULLIF(COUNT(*), 0) AS share
            FROM cve c
            LEFT JOIN tagged t ON t.cve_id = c.cve_id
            WHERE {clause}
            GROUP BY year
            ORDER BY year
            """,
            conn,
            params=[*tags, *params],
        )
    finally:
        conn.close()


# ============================================================
# Threat intel (intel_string_list)
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_intel_kind_dist(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Counts in ``intel_string_list`` by ``kind`` (actor / malware / campaign /
    osv_package / etc.).

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(kind, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT COALESCE(NULLIF(trim(s.kind),''),'(unset)') AS kind,
                   COUNT(*) AS n
            FROM intel_string_list s
            JOIN cve c ON c.cve_id = s.cve_id
            WHERE {clause}
            GROUP BY kind
            ORDER BY n DESC
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_top_intel_values(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    kind: str,
    top_n: int,
) -> pd.DataFrame:
    """
    Top distinct ``intel_string_list.value`` for one ``kind``.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :param kind: ``intel_string_list.kind`` to filter on.
    :type kind: str
    :param top_n: Maximum values to return.
    :type top_n: int
    :return: ``(value, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT trim(s.value) AS value, COUNT(*) AS n
            FROM intel_string_list s
            JOIN cve c ON c.cve_id = s.cve_id
            WHERE s.kind = ? AND trim(coalesce(s.value,'')) <> ''
              AND {clause}
            GROUP BY value
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[kind, *params, top_n],
        )
    finally:
        conn.close()


# ============================================================
# Lifecycle & latency
# ============================================================


@st.cache_data(ttl=60, show_spinner=False)
def load_published_modified_lag(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.Series:
    """
    Per-CVE lag (days) between ``published`` and ``modified``.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: Series of integer days, name ``lag_days``.
    :rtype: pd.Series
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        rows = conn.execute(
            f"""
            SELECT CAST(julianday(c.modified) - julianday(c.published) AS INTEGER) AS d
            FROM cve c
            WHERE trim(coalesce(c.modified,'')) <> ''
              AND substr(trim(c.modified),1,4) >= '1970'
              AND {clause}
            """,
            params,
        ).fetchall()
    finally:
        conn.close()
    return pd.Series([r[0] for r in rows if r[0] is not None], dtype="float64", name="lag_days")


@st.cache_data(ttl=60, show_spinner=False)
def load_discovered_published_lag(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.Series:
    """
    Per-CVE lag (days) between ``discovered`` and ``published``.

    Many ``discovered`` values are placeholders (``0001-01-01``); those are
    filtered out via ``substr(...,1,4) >= '1970'``.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: Series of integer days, name ``lag_days``.
    :rtype: pd.Series
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        rows = conn.execute(
            f"""
            SELECT CAST(julianday(c.published) - julianday(c.discovered) AS INTEGER) AS d
            FROM cve c
            WHERE trim(coalesce(c.discovered,'')) <> ''
              AND substr(trim(c.discovered),1,4) >= '1970'
              AND {clause}
            """,
            params,
        ).fetchall()
    finally:
        conn.close()
    return pd.Series([r[0] for r in rows if r[0] is not None], dtype="float64", name="lag_days")


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_listing_lag(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.Series:
    """
    Days between ``cve.published`` and ``kev.date_added``.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: Series of integer days, name ``lag_days``.
    :rtype: pd.Series
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        rows = conn.execute(
            f"""
            SELECT CAST(
                       julianday(substr(trim(k.date_added),1,10))
                       - julianday(substr(trim(c.published),1,10))
                   AS INTEGER) AS d
            FROM kev k
            JOIN cve c ON c.cve_id = k.cve_id
            WHERE k.listed = 1
              AND trim(coalesce(k.date_added,'')) <> ''
              AND {clause}
            """,
            params,
        ).fetchall()
    finally:
        conn.close()
    return pd.Series([r[0] for r in rows if r[0] is not None], dtype="float64", name="lag_days")


@st.cache_data(ttl=60, show_spinner=False)
def load_vuln_status_dist(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    NVD ``vuln_status`` distribution.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(vuln_status, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT COALESCE(NULLIF(trim(c.vuln_status),''),'(unset)') AS vuln_status,
                   COUNT(*) AS n
            FROM cve c
            WHERE {clause}
            GROUP BY vuln_status
            ORDER BY n DESC
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_vuln_status_by_year(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    NVD ``vuln_status`` counts by publication year.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(year, vuln_status, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y', c.published) AS year,
                   COALESCE(NULLIF(trim(c.vuln_status),''),'(unset)') AS vuln_status,
                   COUNT(*) AS n
            FROM cve c
            WHERE {clause}
            GROUP BY year, vuln_status
            ORDER BY year, vuln_status
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_modification_recency_heatmap(
    db_path_str: str, date_min: str | None, date_max: str | None
) -> pd.DataFrame:
    """
    Counts grouped by ``(modified-year, published-year)`` — shows which old
    CVEs are still being touched.

    :param db_path_str: Resolved SQLite path.
    :type db_path_str: str
    :param date_min: Lower bound on ``cve.published``.
    :type date_min: str | None
    :param date_max: Upper bound on ``cve.published``.
    :type date_max: str | None
    :return: ``(mod_year, pub_year, n)``.
    :rtype: pd.DataFrame
    """
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y', c.modified) AS mod_year,
                   strftime('%Y', c.published) AS pub_year,
                   COUNT(*) AS n
            FROM cve c
            WHERE trim(coalesce(c.modified,'')) <> ''
              AND substr(trim(c.modified),1,4) >= '1970'
              AND {clause}
            GROUP BY mod_year, pub_year
            ORDER BY mod_year, pub_year
            """,
            conn,
            params=params,
        )
    finally:
        conn.close()


__all__ = [
    "SEVERITY_COLORS",
    "SEVERITY_ORDER",
    "load_cpe_per_cve_hist",
    "load_cvss_av_pr_heatmap",
    "load_cvss_axis_dist",
    "load_cvss_remote_unauth_funnel",
    "load_cvss_subscore_sample",
    "load_cwe_severity_heatmap",
    "load_discovered_published_lag",
    "load_distinct_dimension_counts",
    "load_enrichment_coverage",
    "load_epss_by_severity",
    "load_epss_density",
    "load_exploit_flag_totals",
    "load_exploit_in_the_wild_monthly",
    "load_exploit_maturity_dist",
    "load_exploit_vs_cvss",
    "load_intel_kind_dist",
    "load_kev_due_date_buckets",
    "load_kev_listing_lag",
    "load_kev_remediation_span",
    "load_kev_required_action_top",
    "load_kev_severity_mix",
    "load_kev_share_by_epss_decile",
    "load_kev_source_split",
    "load_kev_top_product_label",
    "load_kev_top_vendor_project",
    "load_modification_recency_heatmap",
    "load_pipeline_run",
    "load_product_type_dist",
    "load_publications_weekly",
    "load_publications_yoy",
    "load_published_modified_lag",
    "load_ref_tag_dist",
    "load_ref_trust_dist",
    "load_refs_per_cve_hist",
    "load_severity_distribution",
    "load_severity_monthly",
    "load_table_row_counts",
    "load_tag_coverage_yearly",
    "load_top_intel_values",
    "load_top_products",
    "load_top_ref_sources",
    "load_top_vendors_by_product_count",
    "load_vendor_itw_pressure",
    "load_version_range_coverage",
    "load_vuln_status_by_year",
    "load_vuln_status_dist",
]
