"""SQLite read-only accessors and aggregated datasets for the explore app."""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from vulnify.db.readonly import connect_readonly


# Exclude placeholder ``vendor`` rows (empty name) from vendor-facing charts.
_NAMED_VENDOR_PREDICATE = "trim(COALESCE(v.name, '')) <> ''"


def _date_clause(alias: str, date_min: str | None, date_max: str | None) -> tuple[str, list[Any]]:
    parts: list[str] = []
    params: list[Any] = []

    ts = f"trim(ifnull({alias}.published,''))"
    parts.append(f"({ts} <> '')")
    if date_min:
        parts.append(f"substr({ts}, 1, 10) >= ?")
        params.append(date_min[:10])
    if date_max:
        parts.append(f"substr({ts}, 1, 10) <= ?")
        params.append(date_max[:10])

    return " AND ".join(parts), params


@st.cache_data(ttl=60, show_spinner=False)
def load_overview(db_path_str: str, date_min: str | None, date_max: str | None) -> dict[str, Any]:
    clause, params = _date_clause("c", date_min, date_max)

    conn = connect_readonly(db_path_str)
    try:
        cur = conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        with_pub = cur.execute(
            """SELECT COUNT(*) FROM cve c WHERE trim(ifnull(c.published,'')) <> ''"""
        ).fetchone()[0]

        params_f = [*params]
        filtered = cur.execute(f"SELECT COUNT(*) FROM cve c WHERE {clause}", params_f).fetchone()[0]

        row = cur.execute(
            f"""
            SELECT COUNT(*) FROM cve c
            JOIN cvss cv ON cv.cve_id = c.cve_id
            WHERE {clause}
            """,
            [*params],
        ).fetchone()
        with_cvss = row[0] if row else 0

        row = cur.execute(
            f"""
            SELECT COUNT(*) FROM cve c
            JOIN intel i ON i.cve_id = c.cve_id
            WHERE {clause}
              AND i.epss_score IS NOT NULL
            """,
            [*params],
        ).fetchone()
        with_epss = row[0] if row else 0

        row = cur.execute(
            f"""
            SELECT COUNT(*) FROM cve c
            JOIN kev k ON k.cve_id = c.cve_id
            WHERE {clause}
              AND k.listed = 1
            """,
            [*params],
        ).fetchone()
        kev_listed = row[0] if row else 0

        rng = cur.execute(
            """SELECT MIN(substr(trim(published),1,10)), MAX(substr(trim(published),1,10))
               FROM cve WHERE trim(ifnull(published,'')) <> ''"""
        ).fetchone()

        vn = cur.execute(
            """SELECT COUNT(DISTINCT cv.vendor_id)
               FROM cve_vendor cv
               JOIN cve c ON c.cve_id = cv.cve_id
               JOIN vendor v ON v.vendor_id = cv.vendor_id
               WHERE """
            + clause
            + f" AND {_NAMED_VENDOR_PREDICATE}",
            [*params],
        ).fetchone()[0]

        return {
            "total_cves": total,
            "cve_with_published": with_pub,
            "cve_in_filter": filtered,
            "cve_with_cvss": with_cvss,
            "cve_with_epss": with_epss,
            "cve_kev_listed": kev_listed,
            "published_range": rng,
            "distinct_vendors": vn,
            "clause": clause,
            "clause_params": params,
        }
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_top_vendors(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_n: int,
    role: str | None,
) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)
    q = """
        SELECT v.name AS vendor_name, cv.role, COUNT(DISTINCT cv.cve_id) AS cve_count
        FROM cve_vendor cv
        JOIN vendor v ON v.vendor_id = cv.vendor_id
        JOIN cve c ON c.cve_id = cv.cve_id
        WHERE """
    qp = [*params]

    role_filter = ""
    if role == "primary":
        role_filter = " AND cv.role = 'primary' "
    elif role == "affected":
        role_filter = " AND cv.role = 'affected' "

    q += clause + role_filter + f"""
        AND {_NAMED_VENDOR_PREDICATE}
        GROUP BY v.vendor_id, cv.role
        ORDER BY cve_count DESC
        LIMIT ?
    """
    qp.append(top_n)

    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(q, conn, params=qp)
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_vendors_aggregate(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_n: int,
    role: str | None,
) -> pd.DataFrame:
    """One row per vendor: CVE count (optionally one role filter)."""

    clause, params = _date_clause("c", date_min, date_max)

    rf = ""
    if role == "primary":
        rf = " AND cv.role = 'primary' "
    elif role == "affected":
        rf = " AND cv.role = 'affected' "

    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT v.name AS vendor_name, COUNT(DISTINCT cv.cve_id) AS cve_count
            FROM cve_vendor cv
            JOIN vendor v ON v.vendor_id = cv.vendor_id
            JOIN cve c ON c.cve_id = cv.cve_id
            WHERE {clause}
            {rf}
              AND {_NAMED_VENDOR_PREDICATE}
            GROUP BY v.vendor_id
            ORDER BY cve_count DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_n],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_vendor_role_totals(db_path_str: str, date_min: str | None, date_max: str | None) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT cv.role,
                   COUNT(DISTINCT cv.cve_id) AS distinct_cves,
                   COUNT(*) AS edges
            FROM cve_vendor cv
            JOIN cve c ON c.cve_id = cv.cve_id
            JOIN vendor v ON v.vendor_id = cv.vendor_id
            WHERE {clause}
              AND {_NAMED_VENDOR_PREDICATE}
            GROUP BY cv.role
            """,
            conn,
            params=[*params],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cve_vendor_role_mix(db_path_str: str, date_min: str | None, date_max: str | None) -> pd.DataFrame:
    """Per vendor: counts of CVEs appearing as primary-only vs affected, etc."""

    clause, params = _date_clause("c", date_min, date_max)

    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            WITH filtered AS (
                SELECT DISTINCT cv.cve_id
                FROM cve_vendor cv
                JOIN cve c ON c.cve_id = cv.cve_id
                WHERE {clause}
            ),
            vc AS (
                SELECT cv.vendor_id,
                       SUM(CASE WHEN cv.role = 'primary' THEN 1 ELSE 0 END) AS n_primary_edges,
                       SUM(CASE WHEN cv.role = 'affected' THEN 1 ELSE 0 END) AS n_affected_edges
                FROM cve_vendor cv
                JOIN filtered f ON f.cve_id = cv.cve_id
                JOIN vendor v ON v.vendor_id = cv.vendor_id AND {_NAMED_VENDOR_PREDICATE}
                GROUP BY cv.vendor_id
            ),
            roles AS (
                SELECT DISTINCT cv.vendor_id, cv.cve_id,
                       SUM(CASE WHEN cv.role='primary' THEN 1 ELSE 0 END) > 0 AS has_primary,
                       SUM(CASE WHEN cv.role='affected' THEN 1 ELSE 0 END) > 0 AS has_affected
                FROM cve_vendor cv
                JOIN filtered f ON f.cve_id = cv.cve_id
                JOIN vendor v2 ON v2.vendor_id = cv.vendor_id AND trim(COALESCE(v2.name, '')) <> ''
                GROUP BY cv.vendor_id, cv.cve_id
            ),
            summarized AS (
                SELECT vendor_id,
                       SUM(CASE WHEN has_primary AND NOT has_affected THEN 1 ELSE 0 END) AS cves_primary_only,
                       SUM(CASE WHEN NOT has_primary AND has_affected THEN 1 ELSE 0 END) AS cves_affected_only,
                       SUM(CASE WHEN has_primary AND has_affected THEN 1 ELSE 0 END) AS cves_both_roles
                FROM roles
                GROUP BY vendor_id
            )
            SELECT v.name AS vendor_name,
                   s.cves_primary_only, s.cves_affected_only, s.cves_both_roles,
                   vc.n_primary_edges AS edge_primary, vc.n_affected_edges AS edge_affected
            FROM summarized s
            JOIN vendor v ON v.vendor_id = s.vendor_id
            JOIN vc ON vc.vendor_id = s.vendor_id
            ORDER BY (s.cves_primary_only + s.cves_affected_only + s.cves_both_roles) DESC
            LIMIT 100
            """,
            conn,
            params=[*params],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_publications_monthly(db_path_str: str, date_min: str | None, date_max: str | None) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y-%m', c.published) AS ym, COUNT(*) AS n
            FROM cve c
            WHERE strftime('%Y-%m', c.published) IS NOT NULL
              AND trim(ifnull(c.published,'')) <> ''
              AND {clause}
            GROUP BY ym ORDER BY ym
            """,
            conn,
            params=[*params],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_publications_yearly(db_path_str: str, date_min: str | None, date_max: str | None) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y', c.published) AS y, COUNT(*) AS n
            FROM cve c
            WHERE trim(ifnull(c.published,'')) <> ''
              AND {clause}
            GROUP BY y ORDER BY y
            """,
            conn,
            params=[*params],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cna_monthly(db_path_str: str, date_min: str | None, date_max: str | None, top_k: int) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        top_cnas = pd.read_sql_query(
            f"""
            SELECT trim(c.cna) AS cna,
                   COUNT(*) AS n FROM cve c
            WHERE trim(ifnull(c.cna,'')) <> ''
              AND {clause}
            GROUP BY trim(c.cna)
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_k],
        )
        cnas = tuple(top_cnas["cna"].tolist())
        if not cnas:
            return pd.DataFrame(columns=["ym", "cna", "n"])

        placeholders = ",".join(["?"] * len(cnas))

        df = pd.read_sql_query(
            f"""
            SELECT strftime('%Y-%m', c.published) AS ym,
                   trim(c.cna) AS cna,
                   COUNT(*) AS n
            FROM cve c
            WHERE trim(ifnull(c.cna,'')) IN ({placeholders})
              AND trim(ifnull(c.published,'')) <> ''
              AND {clause}
            GROUP BY ym, trim(c.cna)
            ORDER BY ym, cna
            """,
            conn,
            params=[*cnas, *params],
        )
        return df
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cooccurrence_pairs(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_k: int,
    max_pairs: int = 2000,
) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            WITH filtered_cve AS (
                SELECT c.cve_id FROM cve c
                WHERE {clause}
            ),
            vendor_totals AS (
                SELECT cv.vendor_id, COUNT(DISTINCT cv.cve_id) AS n
                FROM cve_vendor cv
                INNER JOIN filtered_cve fc ON fc.cve_id = cv.cve_id
                JOIN vendor v ON v.vendor_id = cv.vendor_id AND {_NAMED_VENDOR_PREDICATE}
                GROUP BY cv.vendor_id
                ORDER BY n DESC
                LIMIT ?
            ),
            top_vendor_ids AS (
                SELECT vendor_id FROM vendor_totals
            ),
            pairs AS (
                SELECT DISTINCT cv.cve_id, cv.vendor_id
                FROM cve_vendor cv
                INNER JOIN filtered_cve fc ON fc.cve_id = cv.cve_id
                INNER JOIN top_vendor_ids t ON t.vendor_id = cv.vendor_id
            )
            SELECT va.name AS vendor_a,
                   vb.name AS vendor_b,
                   COUNT(*) AS shared_cves
            FROM pairs p1
            JOIN pairs p2
              ON p1.cve_id = p2.cve_id AND p1.vendor_id < p2.vendor_id
            JOIN vendor va ON va.vendor_id = p1.vendor_id AND trim(COALESCE(va.name, '')) <> ''
            JOIN vendor vb ON vb.vendor_id = p2.vendor_id AND trim(COALESCE(vb.name, '')) <> ''
            GROUP BY p1.vendor_id, p2.vendor_id
            ORDER BY shared_cves DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_k, max_pairs],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_top_vendor_ids(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    top_k: int,
) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT v.vendor_id, v.name AS vendor_name,
                   COUNT(DISTINCT cv.cve_id) AS cve_count
            FROM vendor v
            JOIN cve_vendor cv ON v.vendor_id = cv.vendor_id
            JOIN cve c ON c.cve_id = cv.cve_id
            WHERE {clause}
              AND {_NAMED_VENDOR_PREDICATE}
            GROUP BY v.vendor_id
            ORDER BY cve_count DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_k],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cvss_year_stats(db_path_str: str, date_min: str | None, date_max: str | None) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)
    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y', c.published) AS pub_year,
                   AVG(mx.max_score) AS avg_max_cvss,
                   COUNT(*) AS n_cves_with_cvss,
                   SUM(CASE WHEN mx.max_score >= 9 THEN 1 ELSE 0 END) AS n_critical
            FROM (
                SELECT cve_id, MAX(score) AS max_score FROM cvss WHERE score IS NOT NULL GROUP BY cve_id
            ) mx
            JOIN cve c ON c.cve_id = mx.cve_id
            WHERE {clause}
              AND mx.max_score IS NOT NULL
            GROUP BY pub_year
            ORDER BY pub_year
            """,
            conn,
            params=[*params],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cwe_totals(db_path_str: str, date_min: str | None, date_max: str | None, top_m: int) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)

    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT cw.cwe_id,
                   cw.name AS cwe_name,
                   COUNT(*) AS n
            FROM cve_cwe cc
            JOIN cwe cw ON cw.cwe_id = cc.cwe_id
            JOIN cve c ON c.cve_id = cc.cve_id
            WHERE {clause}
            GROUP BY cw.cwe_id
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[*params, top_m],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_cwe_monthly_for_ids(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    cwe_ids: tuple[str, ...],
) -> pd.DataFrame:
    if not cwe_ids:
        return pd.DataFrame(columns=["ym", "cwe_id", "cwe_label", "n"])

    clause, params = _date_clause("c", date_min, date_max)
    ph = ",".join(["?"] * len(cwe_ids))

    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y-%m', c.published) AS ym,
                   cc.cwe_id,
                   cw.name AS cwe_name,
                   COUNT(*) AS n
            FROM cve_cwe cc
            JOIN cwe cw ON cw.cwe_id = cc.cwe_id
            JOIN cve c ON c.cve_id = cc.cve_id
            WHERE cc.cwe_id IN ({ph})
              AND trim(ifnull(c.published,'')) <> ''
              AND {clause}
            GROUP BY ym, cc.cwe_id
            ORDER BY ym, cc.cwe_id
            """,
            conn,
            params=[*cwe_ids, *params],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_kev_added_monthly(db_path_str: str, date_min: str | None, date_max: str | None) -> pd.DataFrame:
    clause_cve, params_cve = _date_clause("c", date_min, date_max)

    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT strftime('%Y-%m', trim(k.date_added)) AS ym, COUNT(*) AS n
            FROM kev k
            JOIN cve c ON c.cve_id = k.cve_id
            WHERE k.listed = 1
              AND trim(ifnull(k.date_added,'')) <> ''
              AND {clause_cve}
            GROUP BY ym
            ORDER BY ym
            """,
            conn,
            params=[*params_cve],
        )
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_epss_histogram(db_path_str: str, date_min: str | None, date_max: str | None) -> pd.Series:
    clause, params = _date_clause("c", date_min, date_max)

    conn = connect_readonly(db_path_str)
    try:
        cur = conn.execute(
            f"""
            SELECT i.epss_score FROM intel i
            JOIN cve c ON c.cve_id = i.cve_id
            WHERE {clause}
              AND i.epss_score IS NOT NULL
            """,
            params,
        )
        rows = [r[0] for r in cur.fetchall()]
        return pd.Series(rows, dtype="float64", name="epss_score")
    finally:
        conn.close()


@st.cache_data(ttl=60, show_spinner=False)
def load_epss_cvss_scatter_sample(
    db_path_str: str,
    date_min: str | None,
    date_max: str | None,
    sample_limit: int,
) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)

    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT i.cve_id, i.epss_score,
                   (SELECT MAX(score) FROM cvss x WHERE x.cve_id = i.cve_id) AS cvss_max
            FROM intel i
            JOIN cve c ON c.cve_id = i.cve_id
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
def load_assigner_org_top(db_path_str: str, date_min: str | None, date_max: str | None, top_n: int) -> pd.DataFrame:
    clause, params = _date_clause("c", date_min, date_max)

    conn = connect_readonly(db_path_str)
    try:
        return pd.read_sql_query(
            f"""
            SELECT ifnull(trim(c.assigner_org_id),'(unset)') AS org,
                   COUNT(*) AS n,
                   COUNT(*) * 1.0 / NULLIF((
                       SELECT COUNT(*) FROM cve cx WHERE {clause.replace("c.", "cx.")}
                   ), 0) AS share
            FROM cve c
            WHERE trim(ifnull(c.assigner_org_id,'')) <> ''
              AND {clause}
            GROUP BY org
            ORDER BY n DESC
            LIMIT ?
            """,
            conn,
            params=[*params, *params, top_n],
        )
    finally:
        conn.close()


def cooccurrence_heatmap_df(pairs: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Square matrix of vendor co-occurrence counts."""

    if pairs.empty:
        return pd.DataFrame(), []

    vendors_set: set[str] = set()
    for _, row in pairs.iterrows():
        vendors_set.add(row["vendor_a"])
        vendors_set.add(row["vendor_b"])
    vendors = sorted(vendors_set)

    df = pd.DataFrame(0.0, index=vendors, columns=vendors)
    for _, row in pairs.iterrows():
        a, b, w = row["vendor_a"], row["vendor_b"], float(row["shared_cves"])
        df.loc[a, b] = w
        df.loc[b, a] = w

    return df, vendors


def build_pyvis_graph_html(
    pairs: pd.DataFrame,
    top_vendors: pd.DataFrame,
    node_cap: int = 35,
) -> str:
    """HTML string for Pyvis network (edge weight = shared_cves)."""

    from pyvis.network import Network

    if pairs.empty or top_vendors.empty:
        return "<p>No graph data.</p>"

    net = Network(height="520px", width="100%", bgcolor="#111", font_color="#eee", notebook=False)
    net.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=200)

    names = list(top_vendors["vendor_name"].head(node_cap))
    name_set = set(names)
    for name in names:
        n = int(top_vendors.loc[top_vendors["vendor_name"] == name, "cve_count"].iloc[0])
        net.add_node(name, label=name[:28] + ("…" if len(name) > 28 else ""), size=min(8 + n**0.5, 40), title=name)

    for _, row in pairs.iterrows():
        a, b = row["vendor_a"], row["vendor_b"]
        if a not in name_set or b not in name_set:
            continue
        w = int(row["shared_cves"])
        if w > 0:
            net.add_edge(a, b, value=w, title=f"{w} shared CVEs")

    return net.generate_html()
