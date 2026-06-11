"""Streamlit dashboard for CVE SQLite statistics."""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Load ``.env`` before reading ``VULNIFY_SQLITE_PATH``
import vulnify.settings  # noqa: F401, E402

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from vulnify.settings import get_sqlite_path_from_env

from explore.data import (
    build_pyvis_graph_html,
    cooccurrence_heatmap_df,
    load_assigner_org_top,
    load_cna_monthly,
    load_cooccurrence_pairs,
    load_cve_vendor_role_mix,
    load_cwe_monthly_for_ids,
    load_cwe_totals,
    load_cvss_year_stats,
    load_epss_cvss_scatter_sample,
    load_epss_histogram,
    load_kev_added_monthly,
    load_overview,
    load_publications_monthly,
    load_publications_yearly,
    load_top_vendor_ids,
    load_top_vendors,
    load_vendor_role_totals,
    load_vendors_aggregate,
)
from explore.data_views import (
    SEVERITY_COLORS,
    SEVERITY_ORDER,
    load_cpe_per_cve_hist,
    load_cvss_av_pr_heatmap,
    load_cvss_axis_dist,
    load_cvss_remote_unauth_funnel,
    load_cvss_subscore_sample,
    load_cwe_severity_heatmap,
    load_discovered_published_lag,
    load_distinct_dimension_counts,
    load_enrichment_coverage,
    load_epss_by_severity,
    load_epss_density,
    load_exploit_artefact_source_breakdown,
    load_exploit_artefact_totals,
    load_exploit_flag_totals,
    load_exploit_in_the_wild_monthly,
    load_exploit_maturity_dist,
    load_exploit_vs_cvss,
    load_top_artefact_cves,
    load_intel_kind_dist,
    load_kev_due_date_buckets,
    load_kev_listing_lag,
    load_kev_remediation_span,
    load_kev_required_action_top,
    load_kev_severity_mix,
    load_kev_share_by_epss_decile,
    load_kev_source_split,
    load_kev_top_product_label,
    load_kev_top_vendor_project,
    load_modification_recency_heatmap,
    load_pipeline_run,
    load_product_type_dist,
    load_publications_weekly,
    load_publications_yoy,
    load_published_modified_lag,
    load_ref_tag_dist,
    load_ref_trust_dist,
    load_refs_per_cve_hist,
    load_severity_distribution,
    load_severity_monthly,
    load_table_row_counts,
    load_tag_coverage_yearly,
    load_top_intel_values,
    load_top_products,
    load_top_ref_sources,
    load_top_vendors_by_product_count,
    load_vendor_itw_pressure,
    load_version_range_coverage,
    load_vuln_status_by_year,
    load_vuln_status_dist,
)


# Tags treated as "patch-ish" / "PoC-ish" coverage signals. The reference-tag
# vocabulary mixes CNA-specific stems (``x_refsource_*``) with normalised
# names; the lists below cover what's seen in the wild.
_PATCH_TAGS: tuple[str, ...] = (
    "vendor-advisory",
    "patch",
    "mitigation",
    "x_refsource_CONFIRM",
    "x_refsource_REDHAT",
)
_POC_TAGS: tuple[str, ...] = (
    "exploit",
    "x_refsource_EXPLOIT-DB",
    "signature",
)


def _resolve_db_path(sidebar_path: str) -> Path | None:
    raw = (sidebar_path or "").strip()
    if raw:
        p = Path(raw)
        if not p.is_absolute():
            p = (_PROJECT_ROOT / p).resolve()
        return p if p.is_file() else None
    env_p = get_sqlite_path_from_env()
    return env_p if env_p and env_p.is_file() else None


def _iso(d) -> str:
    return pd.Timestamp(d).strftime("%Y-%m-%d")


def _empty(df) -> bool:
    """True for empty DataFrame/Series, False otherwise."""

    if df is None:
        return True
    if hasattr(df, "empty"):
        return bool(df.empty)
    return len(df) == 0


def _pipeline_freshness_caption(pr_df: pd.DataFrame, today: pd.Timestamp) -> str:
    if pr_df is None or pr_df.empty:
        return "Pipeline state unknown (``pipeline_run`` table empty)."
    parts: list[str] = []
    now_utc = pd.Timestamp.now(tz="UTC")
    for _, row in pr_df.iterrows():
        ts = pd.to_datetime(row["last_completed_at"], errors="coerce", utc=True)
        if pd.isna(ts):
            age = "—"
        else:
            age = f"{int((now_utc - ts).total_seconds() // 86400)}d ago"
        wm = (row.get("last_watermark") or "").strip() or "—"
        parts.append(f"**{row['phase']}** {age} (wm `{wm}`)")
    return "Pipeline freshness — " + " · ".join(parts)


def main() -> None:
    st.set_page_config(page_title="Vulnify explore", layout="wide", initial_sidebar_state="expanded")
    default_env = ""
    gp = get_sqlite_path_from_env()
    if gp and gp.is_file():
        default_env = str(gp)

    with st.sidebar:
        st.header("Data source")
        db_input = st.text_input(
            "SQLite path (leave empty for ``VULNIFY_SQLITE_PATH``)",
            value=default_env,
            placeholder="e.g. vulnify.db",
        )

        db_path = _resolve_db_path(db_input)
        if db_path:
            st.caption(f"Using: `{db_path}`")
        else:
            st.error(
                "No readable SQLite file. Set path above or configure ``VULNIFY_SQLITE_PATH`` in `.env`. "
                f"Repo root is `{_PROJECT_ROOT}`."
            )

        st.header("Filters")
        use_dates = st.checkbox("Filter by published date range", value=False)

        da = pd.Timestamp("1970-01-01").date()
        db_today = pd.Timestamp.now(tz=None).normalize().date()
        sd_min: str | None = None
        sd_max: str | None = None
        if use_dates:
            d_min = st.date_input("Published from", value=da, format="YYYY-MM-DD", max_value=db_today, key="dmin")
            d_max = st.date_input(
                "Published through",
                value=db_today,
                format="YYYY-MM-DD",
                min_value=d_min,
                max_value=db_today,
                key="dmax",
            )
            sd_min, sd_max = _iso(d_min), _iso(d_max)

        st.divider()
        top_n_vendor = st.slider("Top vendors (charts / networks)", min_value=5, max_value=75, value=28, step=1)
        top_cnas = st.slider("Top CNAs multi-series", min_value=3, max_value=25, value=10, step=1)
        top_cwe = st.slider("Top CWE weaknesses", min_value=5, max_value=30, value=12, step=1)
        scatter_sample = st.slider("EPSS scatter sample size", min_value=500, max_value=10_000, value=3500, step=500)
        top_products = st.slider("Top products (Products tab)", min_value=10, max_value=80, value=24, step=2)
        top_intel_n = st.slider("Top intel values per kind", min_value=5, max_value=40, value=12, step=1)

    if not db_path:
        st.stop()

    db_key = str(db_path.resolve())
    today_ts = pd.Timestamp.now(tz=None).normalize()
    today_iso = today_ts.strftime("%Y-%m-%d")

    st.title("CVE statistics")
    ov = load_overview(db_key, sd_min, sd_max)
    filtered = ov["cve_in_filter"]
    if ov["total_cves"] == 0:
        st.warning("CVE table is empty for this database.")
        st.stop()

    def cov_pct(part: float, whole: float) -> float:
        if whole <= 0:
            return 0.0
        return round(100.0 * part / whole, 1)

    filt_note = ""
    if sd_min or sd_max:
        filt_note = f" (within published date filter: **{filtered:,}** CVEs)"

    cols = st.columns(5)
    cols[0].metric("CVEs (filter)", f"{filtered:,}")
    cols[1].metric("CVEs total (database)", f"{ov['total_cves']:,}", help="Unfiltered CVE row count.")
    cols[2].metric("Distinct vendors (filter)", f"{ov['distinct_vendors']:,}")
    cols[3].metric("KEV listed (filter)", f"{ov['cve_kev_listed']:,}")
    cols[4].metric(
        "Published span (global)",
        f"{ov['published_range'][0] or '—'} … {ov['published_range'][1] or '—'}",
        help="Minimum and maximum published timestamps in the database.",
    )

    st.caption(
        "Coverage vs filtered set: CVSS-linked "
        f"{cov_pct(ov['cve_with_cvss'], filtered)}% · EPSS "
        f"{cov_pct(ov['cve_with_epss'], filtered)}% · CVEs with a published timestamp "
        f"{cov_pct(ov['cve_with_published'], ov['total_cves'])}% (global)."
        + filt_note
    )

    pr_df = load_pipeline_run(db_key)
    st.caption(_pipeline_freshness_caption(pr_df, today_ts))

    (
        tab_over,
        tab_ven,
        tab_trend,
        tab_link,
        tab_sev,
        tab_enrich,
        tab_exploit,
        tab_kev_deep,
        tab_vector,
        tab_products,
        tab_refs,
        tab_intel,
        tab_lifecycle,
        tab_health,
    ) = st.tabs(
        [
            "Overview",
            "Vendors",
            "Trends",
            "Vendor links",
            "Severity & CWE",
            "Enrichment",
            "Exploit landscape",
            "KEV deep dive",
            "CVSS vector",
            "Products & CPEs",
            "References",
            "Threat intel",
            "Lifecycle",
            "Pipeline health",
        ]
    )

    # =====================================================================
    # Overview
    # =====================================================================
    with tab_over:
        st.subheader("Enrichment coverage")
        cov_df = load_enrichment_coverage(db_key, sd_min, sd_max)
        if _empty(cov_df):
            st.info("No data in the filter window.")
        else:
            cov_df = cov_df.copy()
            cov_df["share_pct"] = (cov_df["share"] * 100.0).round(2)
            cov_df["missing"] = cov_df["total"] - cov_df["present"]
            cov_long = cov_df.melt(
                id_vars=["enrichment"],
                value_vars=["present", "missing"],
                var_name="state",
                value_name="n",
            )
            fig_cov = px.bar(
                cov_long,
                x="n",
                y="enrichment",
                color="state",
                orientation="h",
                title="CVEs with each enrichment present (filter window)",
                color_discrete_map={"present": "#2ecc71", "missing": "#7f8c8d"},
                category_orders={"enrichment": cov_df["enrichment"].tolist()[::-1]},
            )
            fig_cov.update_layout(
                margin=dict(l=200, r=28, t=48, b=36),
                yaxis_title=None,
                xaxis_title="CVE count",
                legend_title_text=None,
            )
            cov_a, cov_b = st.columns([3, 2])
            cov_a.plotly_chart(fig_cov, use_container_width=True)
            cov_b.dataframe(
                cov_df[["enrichment", "present", "share_pct"]].rename(
                    columns={"share_pct": "share %"}
                ),
                use_container_width=True,
                hide_index=True,
            )

        st.subheader("Assigner organisation")
        org_df = load_assigner_org_top(db_key, sd_min, sd_max, 25)
        if org_df.empty:
            st.info("No assigner data in this window.")
        else:
            o1, o2 = st.columns(2)
            fig_org = px.bar(
                org_df.head(20),
                x="n",
                y="org",
                orientation="h",
                title="Top assigners by CVE count",
            )
            fig_org.update_layout(
                yaxis=dict(categoryorder="total ascending"),
                margin=dict(l=180, r=28, t=48, b=40),
                xaxis_title="CVEs",
                yaxis_title=None,
            )
            o1.plotly_chart(fig_org, use_container_width=True)

            pie_df = org_df.head(12).copy()
            rest = org_df["n"].iloc[12:].sum() if len(org_df) > 12 else 0
            if rest > 0:
                pie_df = pd.concat(
                    [pie_df, pd.DataFrame([{"org": "Other", "n": rest, "share": None}])],
                    ignore_index=True,
                )
            fig_pie = px.pie(
                pie_df,
                values="n",
                names="org",
                title="Assigner share (top 12 + other)",
                hole=0.38,
            )
            fig_pie.update_traces(textposition="inside", textinfo="percent+label")
            fig_pie.update_layout(margin=dict(l=20, r=20, t=48, b=20), showlegend=False)
            o2.plotly_chart(fig_pie, use_container_width=True)

        st.subheader("Vendor linkage roles")
        vrt = load_vendor_role_totals(db_key, sd_min, sd_max)
        if vrt.empty:
            st.info("No vendor rows.")
        else:
            r1, r2 = st.columns(2)
            fig_roles = px.bar(
                vrt,
                x="role",
                y="distinct_cves",
                color="role",
                title="Distinct CVEs per ``cve_vendor`` role",
            )
            fig_roles.update_layout(showlegend=False, xaxis_title=None, yaxis_title="CVEs")
            r1.plotly_chart(fig_roles, use_container_width=True)

            mx = load_cve_vendor_role_mix(db_key, sd_min, sd_max)
            if mx.empty:
                r2.info("No vendor-role mix.")
            else:
                mx = mx.head(14)
                long_mx = mx.melt(
                    id_vars=["vendor_name"],
                    value_vars=["cves_primary_only", "cves_affected_only", "cves_both_roles"],
                    var_name="pattern",
                    value_name="n",
                )
                long_mx["pattern"] = long_mx["pattern"].str.replace("cves_", "").str.replace("_", " ").str.title()

                fig_stack = px.bar(
                    long_mx,
                    x="n",
                    y="vendor_name",
                    color="pattern",
                    orientation="h",
                    title="CVE role pattern (top vendors)",
                    category_orders={"vendor_name": mx["vendor_name"].tolist()[::-1]},
                )
                fig_stack.update_layout(
                    barmode="stack",
                    margin=dict(l=200, r=28, t=48, b=36),
                    yaxis_title=None,
                    xaxis_title="Distinct CVE count",
                    legend_title_text="Pattern",
                )
                r2.plotly_chart(fig_stack, use_container_width=True)

    # =====================================================================
    # Vendors
    # =====================================================================
    with tab_ven:
        rf = st.radio("Vendor linkage role filter", ["all links", "primary only", "affected only"], horizontal=True)
        role_key = {"all links": None, "primary only": "primary", "affected only": "affected"}[rf]

        top_v_agg = load_vendors_aggregate(db_key, sd_min, sd_max, top_n_vendor, role_key)

        v1, v2 = st.columns(2)
        if top_v_agg.empty:
            v1.info("No vendors matched filters.")
            v2.info("—")
        else:
            fig_vbar = px.bar(
                top_v_agg.sort_values("cve_count"),
                x="cve_count",
                y="vendor_name",
                orientation="h",
                title=f"Distinct CVEs per vendor (top {top_n_vendor})",
            )
            fig_vbar.update_layout(yaxis=dict(categoryorder="total ascending"), margin=dict(l=220, r=28, t=48, b=40))
            v1.plotly_chart(fig_vbar, use_container_width=True)

            tm_df = top_v_agg.copy()
            tm_df["_root"] = "Vendors"
            fig_tree = px.treemap(
                tm_df,
                path=["_root", "vendor_name"],
                values="cve_count",
                title="Vendor share (area ∝ CVE count)",
            )
            fig_tree.update_traces(textinfo="label+value")
            v2.plotly_chart(fig_tree, use_container_width=True)

        st.subheader("Primary vs affected load (top vendors)")
        tbl_role = load_top_vendors(db_key, sd_min, sd_max, max(24, top_n_vendor), None)
        if tbl_role.empty:
            st.info("No per-role vendor data.")
        else:
            pt = tbl_role.pivot_table(index="vendor_name", columns="role", values="cve_count", fill_value=0)
            pt["total"] = pt.sum(axis=1)
            pt = pt.sort_values("total", ascending=False).head(16).drop(columns="total")
            long_pr = pt.reset_index().melt(
                id_vars=["vendor_name"], var_name="role", value_name="cve_count"
            )
            fig_group = px.bar(
                long_pr,
                x="cve_count",
                y="vendor_name",
                color="role",
                orientation="h",
                barmode="group",
                title="Primary vs affected edge counts (top 16)",
                category_orders={"vendor_name": pt.index.tolist()[::-1]},
            )
            fig_group.update_layout(
                margin=dict(l=200, r=28, t=48, b=36),
                yaxis_title=None,
                xaxis_title="Rows in ``cve_vendor``",
                legend_title_text="Role",
            )
            st.plotly_chart(fig_group, use_container_width=True)

    # =====================================================================
    # Trends
    # =====================================================================
    with tab_trend:
        pub_m = load_publications_monthly(db_key, sd_min, sd_max)

        tm1, tm2 = st.columns(2)

        rm_w = int(st.slider("Rolling mean window (months)", min_value=0, max_value=24, value=6, step=1))

        if pub_m.empty:
            tm1.info("No dated publications in filter.")
            tm2.info("No yearly data.")
        else:
            dm = pub_m.rename(columns={"ym": "month", "n": "cve_count"}).sort_values("month")
            win = rm_w if rm_w > 0 else 1
            dm["cve_count_roll"] = dm["cve_count"].rolling(window=win, min_periods=1).mean()

            fig_pub = go.Figure()
            fig_pub.add_trace(
                go.Bar(
                    x=dm["month"],
                    y=dm["cve_count"],
                    name="Monthly count",
                    marker_color="#4a69bd",
                    opacity=0.72,
                )
            )
            fig_pub.add_trace(
                go.Scatter(
                    x=dm["month"],
                    y=dm["cve_count_roll"],
                    name=f"{rm_w}-month rolling mean",
                    mode="lines",
                    line=dict(width=3, color="#e55039"),
                )
            )
            fig_pub.update_layout(
                title="CVE publications — monthly bars and rolling mean",
                margin=dict(l=48, r=48, t=52, b=48),
                yaxis_title="CVE count",
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                hovermode="x unified",
            )
            tm1.plotly_chart(fig_pub, use_container_width=True)

            pub_y = load_publications_yearly(db_key, sd_min, sd_max)
            fig_y = px.bar(pub_y, x="y", y="n", title="CVE count by publication year")
            tm2.plotly_chart(fig_y, use_container_width=True)

            cna_df = load_cna_monthly(db_key, sd_min, sd_max, top_cnas)
            if not cna_df.empty:
                st.markdown("#### CNAs — top CNA share over time")
                wide = cna_df.pivot_table(index="ym", columns="cna", values="n", fill_value=0)
                wide = wide.sort_index()
                fig_cna = px.area(
                    wide,
                    title=f"Monthly CVE publications by top-{top_cnas} CNA",
                    labels={"value": "CVEs", "ym": "Month", "cna": "CNA"},
                )
                fig_cna.update_layout(legend=dict(orientation="h", yanchor="bottom", y=-0.48, font=dict(size=10)))
                st.plotly_chart(fig_cna, use_container_width=True)

        st.subheader("Severity-stacked publication volume")
        sev_m = load_severity_monthly(db_key, sd_min, sd_max)
        if _empty(sev_m):
            st.info("No CVSS-linked CVEs in this filter.")
        else:
            wide_sev = sev_m.pivot_table(index="ym", columns="severity", values="n", fill_value=0)
            ordered_cols = [c for c in SEVERITY_ORDER if c in wide_sev.columns]
            wide_sev = wide_sev[ordered_cols].sort_index()
            fig_sev_stack = px.area(
                wide_sev,
                title="Monthly CVE counts by severity (max-CVSS bucket)",
                color_discrete_map=SEVERITY_COLORS,
                labels={"value": "CVEs", "ym": "Month", "severity": "Severity"},
            )
            fig_sev_stack.update_layout(
                legend=dict(orientation="h", yanchor="bottom", y=-0.32),
                margin=dict(l=40, r=20, t=48, b=40),
            )
            st.plotly_chart(fig_sev_stack, use_container_width=True)

        st.subheader("Year-over-year overlay")
        yoy = load_publications_yoy(db_key, sd_min, sd_max)
        if _empty(yoy):
            st.info("No data for YoY overlay.")
        else:
            yoy = yoy.dropna(subset=["year"]).copy()
            yoy["year"] = yoy["year"].astype(int)
            recent_years = sorted(yoy["year"].unique())[-8:]
            yoy = yoy[yoy["year"].isin(recent_years)]
            fig_yoy = px.line(
                yoy,
                x="month",
                y="n",
                color="year",
                markers=True,
                title="CVE publications per month, by year (last 8 years)",
                labels={"month": "Month of year", "n": "CVEs"},
            )
            fig_yoy.update_xaxes(tickmode="linear", dtick=1)
            fig_yoy.update_layout(margin=dict(l=40, r=20, t=48, b=40))
            st.plotly_chart(fig_yoy, use_container_width=True)

        st.subheader("Weekly granularity")
        wk = load_publications_weekly(db_key, sd_min, sd_max)
        if _empty(wk):
            st.info("No weekly data.")
        else:
            wk_tail = wk.tail(int(st.slider("Weeks shown", 12, 260, 156, step=4))).copy()
            fig_wk = px.bar(wk_tail, x="yw", y="n", title="CVE publications per ISO week (recent window)")
            fig_wk.update_layout(xaxis_title=None, yaxis_title="CVEs", margin=dict(l=40, r=20, t=48, b=40))
            st.plotly_chart(fig_wk, use_container_width=True)

    # =====================================================================
    # Vendor links
    # =====================================================================
    with tab_link:
        st.markdown(
            "Co-occurrence counts how many CVEs list **both** vendors among the **top‑K** set by CVE volume. "
            "Large K can be slow on very large databases."
        )
        pairs = load_cooccurrence_pairs(db_key, sd_min, sd_max, top_n_vendor)
        tv = load_top_vendor_ids(db_key, sd_min, sd_max, top_n_vendor)

        if pairs.empty:
            st.info("No multi-vendor co-occurrences in this top‑K vendor window (or no data).")
        else:
            st.subheader("Strongest vendor pairs")
            edge_df = pairs.head(18).copy()
            edge_df["pair"] = edge_df["vendor_a"].str.slice(0, 22) + " ↔ " + edge_df["vendor_b"].str.slice(0, 22)
            fig_edges = px.bar(
                edge_df.sort_values("shared_cves"),
                x="shared_cves",
                y="pair",
                orientation="h",
                title="Shared CVE count (top pairs)",
            )
            fig_edges.update_layout(
                margin=dict(l=280, r=28, t=48, b=36),
                yaxis_title=None,
                xaxis_title="Shared CVEs",
            )
            st.plotly_chart(fig_edges, use_container_width=True)

            mat, _names = cooccurrence_heatmap_df(pairs.head(300))
            if not mat.empty:
                st.subheader("Co-occurrence heatmap")
                fig_hm = px.imshow(
                    mat,
                    text_auto=False,
                    aspect="equal",
                    color_continuous_scale="Blues",
                    title="Shared CVE counts (symmetric)",
                )
                fig_hm.update_layout(xaxis_tickangle=-42, margin=dict(l=100, r=60, t=48, b=120))
                st.plotly_chart(fig_hm, use_container_width=True)

            st.subheader("Interactive vendor graph")
            try:
                html_g = build_pyvis_graph_html(pairs, tv, node_cap=min(38, top_n_vendor))
                components.html(html_g, height=560, scrolling=True)
            except Exception as ex:  # pragma: no cover
                st.warning(f"Graph render failed: {ex}")

    # =====================================================================
    # Severity & CWE
    # =====================================================================
    with tab_sev:
        st.subheader("Severity distribution (max CVSS per CVE)")
        sev_dist = load_severity_distribution(db_key, sd_min, sd_max)
        if _empty(sev_dist):
            st.info("No CVSS-linked CVEs in this filter.")
        else:
            sev_dist = sev_dist.copy()
            sev_dist["severity"] = pd.Categorical(
                sev_dist["severity"], categories=SEVERITY_ORDER, ordered=True
            )
            sev_dist = sev_dist.sort_values("severity")
            sev_a, sev_b = st.columns(2)
            fig_sev_donut = px.pie(
                sev_dist,
                values="n",
                names="severity",
                title="Severity bucket share",
                hole=0.45,
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
            )
            fig_sev_donut.update_traces(textposition="inside", textinfo="percent+label")
            sev_a.plotly_chart(fig_sev_donut, use_container_width=True)

            fig_sev_bar = px.bar(
                sev_dist,
                x="severity",
                y="n",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                title="Severity bucket counts",
            )
            fig_sev_bar.update_layout(showlegend=False, xaxis_title=None, yaxis_title="CVEs")
            sev_b.plotly_chart(fig_sev_bar, use_container_width=True)

        st.subheader("CVSS (max score per CVE) vs publication year")
        cy = load_cvss_year_stats(db_key, sd_min, sd_max)
        if cy.empty:
            st.info("No CVSS-linked CVEs in this filter.")
        else:
            c1, c2 = st.columns(2)
            fig_avg = px.line(cy, x="pub_year", y="avg_max_cvss", markers=True, title="Average of per-CVE max CVSS")
            c1.plotly_chart(fig_avg, use_container_width=True)
            fig_crit = px.bar(cy, x="pub_year", y="n_critical", title="CVEs with max CVSS ≥ 9 (Critical)")
            c2.plotly_chart(fig_crit, use_container_width=True)

            cy2 = cy.copy()
            cy2["other"] = (cy2["n_cves_with_cvss"] - cy2["n_critical"]).clip(lower=0)
            fig_stack_cvss = go.Figure()
            fig_stack_cvss.add_bar(x=cy2["pub_year"], y=cy2["n_critical"], name="Critical (≥9)", marker_color="#c0392b")
            fig_stack_cvss.add_bar(
                x=cy2["pub_year"], y=cy2["other"], name="Below critical", marker_color="#7f8c8d"
            )
            fig_stack_cvss.update_layout(
                barmode="stack",
                title="CVSS-bearing CVEs: critical vs rest (by publication year)",
                xaxis_title="Year",
                yaxis_title="CVE count",
                margin=dict(l=40, r=28, t=48, b=40),
            )
            st.plotly_chart(fig_stack_cvss, use_container_width=True)

        st.subheader("Exploitability vs impact (CVSS subscores)")
        sub = load_cvss_subscore_sample(db_key, sd_min, sd_max)
        if _empty(sub):
            st.info("No CVSS subscore data in this filter.")
        else:
            fig_sub = px.scatter(
                sub,
                x="exploitability_score",
                y="impact_score",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                category_orders={"severity": list(SEVERITY_ORDER)},
                marginal_x="histogram",
                marginal_y="histogram",
                opacity=0.45,
                hover_data=["cve_id", "score"],
                title="CVSS exploitability × impact (random sample)",
            )
            fig_sub.update_layout(margin=dict(l=40, r=20, t=48, b=40))
            st.plotly_chart(fig_sub, use_container_width=True)

        st.subheader("CWE")
        cwe_top = load_cwe_totals(db_key, sd_min, sd_max, top_cwe)
        if cwe_top.empty:
            st.info("No CWE mappings in this filter.")
        else:
            cwe_top = cwe_top.copy()
            cwe_top["label"] = cwe_top["cwe_id"] + " — " + cwe_top["cwe_name"].fillna("").str.slice(0, 60)
            fig_cwe = px.bar(
                cwe_top.sort_values("n"),
                x="n",
                y="label",
                orientation="h",
                title=f"Top {top_cwe} CWEs (association count)",
            )
            fig_cwe.update_layout(margin=dict(l=320, r=28, t=44, b=36))
            st.plotly_chart(fig_cwe, use_container_width=True)

            ids = tuple(cwe_top["cwe_id"].tolist())
            cm = load_cwe_monthly_for_ids(db_key, sd_min, sd_max, ids)
            if not cm.empty:
                cm = cm.copy()
                cm["cwe_label"] = cm["cwe_id"].astype(str) + " · " + cm["cwe_name"].fillna("").str.slice(0, 36)
                wide_c = cm.pivot_table(index="ym", columns="cwe_label", values="n", fill_value=0).sort_index()
                fig_cm = px.area(
                    wide_c,
                    title="CWE mentions by publication month (top CWEs)",
                    labels={"value": "count", "ym": "Month"},
                )
                fig_cm.update_layout(legend=dict(orientation="h", yanchor="bottom", y=-0.32, font=dict(size=9)))
                st.plotly_chart(fig_cm, use_container_width=True)

            cw_sev = load_cwe_severity_heatmap(db_key, sd_min, sd_max, top_cwe)
            if not _empty(cw_sev):
                cw_sev = cw_sev.copy()
                cw_sev["cwe_label"] = (
                    cw_sev["cwe_id"].astype(str)
                    + " · "
                    + cw_sev["cwe_name"].fillna("").str.slice(0, 30)
                )
                wide_cs = cw_sev.pivot_table(
                    index="cwe_label", columns="severity", values="n", fill_value=0
                )
                ordered_cols = [c for c in SEVERITY_ORDER if c in wide_cs.columns]
                wide_cs = wide_cs[ordered_cols]
                wide_cs = wide_cs.loc[wide_cs.sum(axis=1).sort_values(ascending=False).index]
                fig_cwe_sev = px.imshow(
                    wide_cs,
                    color_continuous_scale="Reds",
                    aspect="auto",
                    title="CWE × severity heatmap (top CWEs)",
                    labels={"color": "CVEs"},
                )
                fig_cwe_sev.update_layout(
                    margin=dict(l=240, r=40, t=48, b=40),
                    yaxis_title=None,
                    xaxis_title="Severity",
                )
                st.plotly_chart(fig_cwe_sev, use_container_width=True)

    # =====================================================================
    # Enrichment
    # =====================================================================
    with tab_enrich:
        st.subheader("CISA KEV — date added (month)")
        kv = load_kev_added_monthly(db_key, sd_min, sd_max)
        if kv.empty:
            st.info("No KEV rows with dates in filter.")
        else:
            st.plotly_chart(
                px.bar(kv, x="ym", y="n", title="KEV listings by month (date_added)"),
                use_container_width=True,
            )

        st.subheader("EPSS score distribution")
        s = load_epss_histogram(db_key, sd_min, sd_max)
        if s.empty:
            st.info("No EPSS scores in filter.")
        else:
            fig_ep = px.histogram(s, nbins=60, title="EPSS scores (filtered CVEs)")
            st.plotly_chart(fig_ep, use_container_width=True)

        st.subheader("EPSS vs max CVSS (random sample)")
        sc = load_epss_cvss_scatter_sample(db_key, sd_min, sd_max, scatter_sample)
        sc = sc.dropna(subset=["cvss_max"])
        if sc.empty:
            st.info("Need both EPSS and at least one CVSS score in the sample.")
        else:
            fig_sc = px.scatter(
                sc,
                x="cvss_max",
                y="epss_score",
                hover_data=["cve_id"],
                marginal_x="histogram",
                marginal_y="histogram",
                title="EPSS vs per-CVE max CVSS",
                opacity=0.35,
            )
            st.plotly_chart(fig_sc, use_container_width=True)

        st.subheader("EPSS by severity (boxplot)")
        eb = load_epss_by_severity(db_key, sd_min, sd_max)
        if _empty(eb):
            st.info("No EPSS-linked CVEs.")
        else:
            eb = eb.copy()
            eb["severity"] = pd.Categorical(
                eb["severity"], categories=SEVERITY_ORDER, ordered=True
            )
            fig_eb = px.box(
                eb.sort_values("severity"),
                x="severity",
                y="epss_score",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                points="outliers",
                title="EPSS score distribution by severity bucket",
            )
            fig_eb.update_layout(showlegend=False, xaxis_title=None, yaxis_title="EPSS score")
            st.plotly_chart(fig_eb, use_container_width=True)

        st.subheader("EPSS-percentile × CVSS density")
        dens = load_epss_density(db_key, sd_min, sd_max)
        if _empty(dens):
            st.info("No data for density.")
        else:
            wide_d = dens.pivot_table(
                index="cvss_bin", columns="pct_bin", values="n", fill_value=0
            )
            fig_d = px.imshow(
                wide_d,
                color_continuous_scale="Viridis",
                aspect="auto",
                title="2-D density: EPSS percentile (x) × max CVSS (y)",
                labels={"color": "CVE count"},
            )
            fig_d.update_layout(margin=dict(l=140, r=40, t=48, b=80), xaxis_tickangle=-30)
            st.plotly_chart(fig_d, use_container_width=True)

        st.subheader("KEV listing share by EPSS decile")
        kd = load_kev_share_by_epss_decile(db_key, sd_min, sd_max)
        if _empty(kd):
            st.info("No EPSS data for decile breakdown.")
        else:
            kd = kd.copy()
            kd["share_pct"] = kd["kev_share"] * 100.0
            fig_kd = px.bar(
                kd,
                x="decile",
                y="share_pct",
                title="% of CVEs in each EPSS-percentile decile that are KEV-listed",
                labels={"decile": "EPSS decile (0 = lowest, 9 = highest)", "share_pct": "% KEV"},
            )
            fig_kd.update_traces(marker_color="#c0392b")
            st.plotly_chart(fig_kd, use_container_width=True)

    # =====================================================================
    # Exploit landscape
    # =====================================================================
    with tab_exploit:
        st.markdown(
            "``exploit`` summary signals plus the ``exploit_artefact`` evidence "
            "layer. ``public_poc`` (Nuclei + Exploit-DB) and ``metasploit`` are "
            "tri-state — counted here only when ``= 1`` (assessed and present); "
            "``in_the_wild`` / ``ransomware`` mirror CISA KEV."
        )

        flags = load_exploit_flag_totals(db_key, sd_min, sd_max)
        f_cols = st.columns(5)
        f_cols[0].metric("Total CVEs", f"{flags.get('total', 0):,}")
        f_cols[1].metric("In-the-wild", f"{flags.get('in_the_wild', 0):,}")
        f_cols[2].metric("Public PoC", f"{flags.get('public_poc', 0):,}")
        f_cols[3].metric("Metasploit", f"{flags.get('metasploit', 0):,}")
        f_cols[4].metric("Ransomware", f"{flags.get('ransomware', 0):,}")

        st.subheader("Exploit artefacts")
        art = load_exploit_artefact_totals(db_key, sd_min, sd_max)
        a_cols = st.columns(5)
        a_cols[0].metric("Total artefacts", f"{art.get('total', 0):,}")
        a_cols[1].metric("CVEs with evidence", f"{art.get('distinct_cves', 0):,}")
        a_cols[2].metric("Nuclei", f"{art.get('nuclei', 0):,}")
        a_cols[3].metric("Exploit-DB", f"{art.get('exploitdb', 0):,}")
        a_cols[4].metric("Metasploit", f"{art.get('metasploit', 0):,}")

        ab = load_exploit_artefact_source_breakdown(db_key, sd_min, sd_max)
        if _empty(ab):
            st.info(
                "No exploit artefacts in this window. Run the nuclei / exploitdb "
                "/ metasploit gather phases to populate them."
            )
        else:
            ac1, ac2 = st.columns([3, 2])
            fig_ab = px.bar(
                ab,
                x="source",
                y="n",
                color="confidence",
                title="Artefacts by source and provenance confidence",
                labels={"n": "artefacts", "source": "source", "confidence": "confidence"},
                color_discrete_map={
                    "exact": "#27ae60",
                    "parsed": "#e67e22",
                    "heuristic": "#7f8c8d",
                },
            )
            fig_ab.update_layout(xaxis_title=None)
            ac1.plotly_chart(fig_ab, use_container_width=True)

            top_art = load_top_artefact_cves(db_key, sd_min, sd_max, 15)
            if not _empty(top_art):
                ac2.caption("Most-evidenced CVEs")
                ac2.dataframe(
                    top_art.rename(
                        columns={"cve_id": "CVE", "artefacts": "#", "sources": "src"}
                    )[["CVE", "#", "src"]],
                    hide_index=True,
                    use_container_width=True,
                )

        st.subheader("Exploit maturity distribution")
        em = load_exploit_maturity_dist(db_key, sd_min, sd_max)
        if _empty(em):
            st.info("No exploit rows.")
        else:
            fig_em = px.bar(em, x="maturity", y="n", title="``exploit.maturity`` distribution")
            fig_em.update_layout(xaxis_title=None, yaxis_title="CVEs")
            st.plotly_chart(fig_em, use_container_width=True)

        st.subheader("In-the-wild trend")
        itw = load_exploit_in_the_wild_monthly(db_key, sd_min, sd_max)
        if _empty(itw):
            st.info("No in-the-wild flagged CVEs in this window.")
        else:
            fig_itw = px.bar(itw, x="ym", y="n", title="In-the-wild CVE count by publication month")
            fig_itw.update_layout(xaxis_title=None, yaxis_title="CVEs")
            st.plotly_chart(fig_itw, use_container_width=True)

        st.subheader("Severity comparison: in-the-wild vs other")
        ec = load_exploit_vs_cvss(db_key, sd_min, sd_max)
        if _empty(ec):
            st.info("No data for box comparison.")
        else:
            fig_ec = px.box(
                ec,
                x="grp",
                y="cvss_max",
                color="grp",
                points="outliers",
                title="Max CVSS distribution: in-the-wild vs other",
                labels={"grp": "group", "cvss_max": "Max CVSS"},
                color_discrete_map={"in_the_wild": "#c0392b", "other": "#7f8c8d"},
            )
            fig_ec.update_layout(showlegend=False)
            st.plotly_chart(fig_ec, use_container_width=True)

        st.subheader("Vendor exploit pressure")
        vp = load_vendor_itw_pressure(db_key, sd_min, sd_max, top_n_vendor)
        if _empty(vp):
            st.info("Not enough vendor signal yet (raise the slider or relax the date filter).")
        else:
            vp = vp.copy()
            vp["share_pct"] = vp["share"] * 100.0
            fig_vp = px.bar(
                vp.sort_values("share_pct"),
                x="share_pct",
                y="vendor_name",
                orientation="h",
                hover_data=["n_total", "n_itw"],
                title="Vendors by % of CVEs flagged as in-the-wild (min 25 CVEs each)",
                labels={"share_pct": "% in-the-wild", "vendor_name": "vendor"},
            )
            fig_vp.update_layout(margin=dict(l=200, r=28, t=48, b=36))
            st.plotly_chart(fig_vp, use_container_width=True)

    # =====================================================================
    # KEV deep dive
    # =====================================================================
    with tab_kev_deep:
        st.subheader("KEV catalog source split")
        ks = load_kev_source_split(db_key, sd_min, sd_max)
        if _empty(ks):
            st.info("No KEV-listed CVEs in window.")
        else:
            kc1, kc2 = st.columns(2)
            fig_ks = px.pie(
                ks, values="n", names="source", hole=0.4, title="KEV ``source`` provenance"
            )
            kc1.plotly_chart(fig_ks, use_container_width=True)

            fig_ks_bar = px.bar(ks, x="source", y="n", title="KEV row count by source")
            kc2.plotly_chart(fig_ks_bar, use_container_width=True)

        st.subheader("CISA catalog headlines")
        kvp = load_kev_top_vendor_project(db_key, sd_min, sd_max, 18)
        kpl = load_kev_top_product_label(db_key, sd_min, sd_max, 18)
        kp1, kp2 = st.columns(2)
        if _empty(kvp):
            kp1.info("No vendor_project data.")
        else:
            fig_kvp = px.bar(
                kvp.sort_values("n"),
                x="n",
                y="vendor_project",
                orientation="h",
                title="Top vendor_project (CISA KEV)",
            )
            fig_kvp.update_layout(margin=dict(l=200, r=28, t=48, b=36), yaxis_title=None)
            kp1.plotly_chart(fig_kvp, use_container_width=True)
        if _empty(kpl):
            kp2.info("No product_label data.")
        else:
            fig_kpl = px.bar(
                kpl.sort_values("n"),
                x="n",
                y="product_label",
                orientation="h",
                title="Top product_label (CISA KEV)",
            )
            fig_kpl.update_layout(margin=dict(l=200, r=28, t=48, b=36), yaxis_title=None)
            kp2.plotly_chart(fig_kpl, use_container_width=True)

        st.subheader(f"Remediation pipeline (relative to {today_iso})")
        kdb = load_kev_due_date_buckets(db_key, sd_min, sd_max, today_iso)
        if _empty(kdb):
            st.info("No KEV rows with due dates.")
        else:
            kd1, kd2 = st.columns(2)
            fig_kdb = px.bar(
                kdb,
                x="bucket",
                y="n",
                color="bucket",
                title="KEV remediation buckets",
                color_discrete_map={
                    "Overdue": "#c0392b",
                    "Due ≤ 30d": "#e67e22",
                    "Due ≤ 90d": "#f1c40f",
                    "Due > 90d": "#27ae60",
                    "No due date": "#7f8c8d",
                },
            )
            fig_kdb.update_layout(showlegend=False, xaxis_title=None, yaxis_title="CVEs")
            kd1.plotly_chart(fig_kdb, use_container_width=True)

            span = load_kev_remediation_span(db_key, sd_min, sd_max)
            if span.empty:
                kd2.info("No date_added/due_date pairs.")
            else:
                fig_span = px.histogram(
                    span,
                    nbins=40,
                    title="Days CISA gave between date_added and due_date",
                    labels={"value": "Days"},
                )
                fig_span.update_layout(showlegend=False)
                kd2.plotly_chart(fig_span, use_container_width=True)

        st.subheader("KEV time-to-list")
        listing_lag = load_kev_listing_lag(db_key, sd_min, sd_max)
        if listing_lag.empty:
            st.info("No KEV listing-lag data.")
        else:
            clamped = listing_lag.clip(lower=-365, upper=365 * 5)
            fig_ll = px.histogram(
                clamped,
                nbins=60,
                title="Days between cve.published and kev.date_added (clamped −1y..+5y)",
                labels={"value": "Days"},
            )
            fig_ll.update_layout(showlegend=False)
            st.plotly_chart(fig_ll, use_container_width=True)

        st.subheader("Top required-action phrases")
        ra = load_kev_required_action_top(db_key, sd_min, sd_max, 12)
        if _empty(ra):
            st.info("No required_action data.")
        else:
            ra = ra.copy()
            ra["short"] = ra["required_action"].str.slice(0, 90) + ra["required_action"].apply(
                lambda v: "…" if len(v) > 90 else ""
            )
            fig_ra = px.bar(
                ra.sort_values("n"),
                x="n",
                y="short",
                orientation="h",
                title="Most common KEV required_action verbatim",
                hover_data={"required_action": True, "short": False, "n": True},
            )
            fig_ra.update_layout(margin=dict(l=320, r=28, t=48, b=36), yaxis_title=None)
            st.plotly_chart(fig_ra, use_container_width=True)

        st.subheader("Severity mix: KEV vs non-KEV")
        ksm = load_kev_severity_mix(db_key, sd_min, sd_max)
        if _empty(ksm):
            st.info("No data for severity mix.")
        else:
            ksm = ksm.copy()
            ksm["severity"] = pd.Categorical(
                ksm["severity"], categories=SEVERITY_ORDER, ordered=True
            )
            ksm = ksm.sort_values(["grp", "severity"])
            fig_ksm = px.bar(
                ksm,
                x="grp",
                y="n",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                category_orders={"severity": list(SEVERITY_ORDER)},
                barmode="stack",
                title="Severity composition: KEV vs non-KEV (filter window)",
            )
            fig_ksm.update_layout(xaxis_title=None, yaxis_title="CVEs")
            st.plotly_chart(fig_ksm, use_container_width=True)

            normalised = ksm.copy()
            totals = normalised.groupby("grp", observed=True)["n"].transform("sum")
            normalised["share"] = normalised["n"] / totals.replace({0: 1})
            fig_ksm2 = px.bar(
                normalised,
                x="grp",
                y="share",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                category_orders={"severity": list(SEVERITY_ORDER)},
                barmode="stack",
                title="Severity share: KEV vs non-KEV (normalised)",
            )
            fig_ksm2.update_layout(yaxis_tickformat=".0%", xaxis_title=None, yaxis_title=None)
            st.plotly_chart(fig_ksm2, use_container_width=True)

    # =====================================================================
    # CVSS vector anatomy
    # =====================================================================
    with tab_vector:
        st.subheader("CVSS vector axis distribution")
        ax_df = load_cvss_axis_dist(db_key, sd_min, sd_max)
        if _empty(ax_df):
            st.info("No CVSS rows in this filter.")
        else:
            axis_order = [
                "AV",
                "AC",
                "PR",
                "UI",
                "Scope",
                "Confidentiality",
                "Integrity",
                "Availability",
            ]
            for chunk_start in range(0, len(axis_order), 4):
                chunk = axis_order[chunk_start : chunk_start + 4]
                cols = st.columns(len(chunk))
                for col, axis in zip(cols, chunk):
                    sub = ax_df[ax_df["axis"] == axis].sort_values("n", ascending=False)
                    if sub.empty:
                        col.info(f"No {axis} data.")
                        continue
                    fig_ax = px.bar(
                        sub,
                        x="value",
                        y="n",
                        title=axis,
                        labels={"value": "value", "n": "CVSS rows"},
                    )
                    fig_ax.update_layout(showlegend=False, margin=dict(l=20, r=20, t=40, b=80))
                    fig_ax.update_xaxes(tickangle=-30)
                    col.plotly_chart(fig_ax, use_container_width=True)

        st.subheader("AV × PR heatmap")
        av_pr = load_cvss_av_pr_heatmap(db_key, sd_min, sd_max)
        if _empty(av_pr):
            st.info("No AV/PR data.")
        else:
            wide_avpr = av_pr.pivot_table(index="av", columns="pr", values="n", fill_value=0)
            fig_avpr = px.imshow(
                wide_avpr,
                text_auto=True,
                color_continuous_scale="Blues",
                aspect="auto",
                title="Attack vector × privileges required (CVSS row counts)",
                labels={"color": "rows"},
            )
            fig_avpr.update_layout(margin=dict(l=120, r=40, t=48, b=80))
            st.plotly_chart(fig_avpr, use_container_width=True)

        st.subheader("Remote-unauth-critical funnel")
        funnel = load_cvss_remote_unauth_funnel(db_key, sd_min, sd_max)
        if _empty(funnel):
            st.info("No CVSS data for funnel.")
        else:
            fig_fun = go.Figure(
                go.Funnel(
                    y=funnel["stage"],
                    x=funnel["n"],
                    textinfo="value+percent initial",
                )
            )
            fig_fun.update_layout(
                title="Filtering CVEs down to remote, unauth-only, no-UI, critical",
                margin=dict(l=120, r=40, t=48, b=20),
            )
            st.plotly_chart(fig_fun, use_container_width=True)

        st.subheader("Exploitability vs impact subscore (anchor view)")
        sub2 = load_cvss_subscore_sample(db_key, sd_min, sd_max)
        if _empty(sub2):
            st.info("No subscore data.")
        else:
            fig_sub2 = px.density_heatmap(
                sub2,
                x="exploitability_score",
                y="impact_score",
                nbinsx=20,
                nbinsy=20,
                color_continuous_scale="Inferno",
                title="Subscore density (sampled)",
            )
            st.plotly_chart(fig_sub2, use_container_width=True)

    # =====================================================================
    # Products & CPEs
    # =====================================================================
    with tab_products:
        st.subheader("Top products by CVE count")
        tp = load_top_products(db_key, sd_min, sd_max, top_products)
        if _empty(tp):
            st.info("No product data in this filter.")
        else:
            tp = tp.copy()
            tp["label"] = tp["vendor_name"].str.slice(0, 22) + " · " + tp["product_name"].str.slice(0, 36)
            fig_tp = px.bar(
                tp.sort_values("n"),
                x="n",
                y="label",
                orientation="h",
                title=f"Top {top_products} (vendor, product) pairs by CVE count",
                hover_data=["vendor_name", "product_name"],
            )
            fig_tp.update_layout(margin=dict(l=300, r=28, t=48, b=36), yaxis_title=None)
            st.plotly_chart(fig_tp, use_container_width=True)

        st.subheader("Product type distribution")
        ptd = load_product_type_dist(db_key)
        if _empty(ptd):
            st.info("No product_type rows.")
        else:
            fig_ptd = px.bar(ptd, x="product_type", y="n", title="``product.product_type`` distribution")
            fig_ptd.update_layout(showlegend=False, xaxis_title=None, yaxis_title="Products")
            st.plotly_chart(fig_ptd, use_container_width=True)
            if ptd["product_type"].nunique() == 1:
                st.caption(
                    "Heads-up — all rows are tagged ``UNKNOWN`` because the ingestion path "
                    "doesn't classify product type yet. Will fill out as the product-type "
                    "extractor lands."
                )

        st.subheader("CPE matches per CVE")
        cpe_h = load_cpe_per_cve_hist(db_key, sd_min, sd_max)
        if _empty(cpe_h):
            st.info("No CPE matches.")
        else:
            cpe_clamped = cpe_h.copy()
            cap = int(st.slider("Clamp CPE-match count tail at", 5, 200, 50, step=5))
            cpe_clamped["bin"] = cpe_clamped["matches"].clip(upper=cap)
            cpe_binned = cpe_clamped.groupby("bin", as_index=False)["cves"].sum()
            cpe_binned["bin_label"] = cpe_binned["bin"].astype(str)
            cpe_binned.loc[cpe_binned["bin"] == cap, "bin_label"] = f"{cap}+"
            fig_cpe = px.bar(
                cpe_binned,
                x="bin_label",
                y="cves",
                title=f"Distribution of CPE-match count per CVE (clamped {cap}+)",
                labels={"bin_label": "matches per CVE", "cves": "CVE count"},
            )
            st.plotly_chart(fig_cpe, use_container_width=True)

        st.subheader("Top vendors by distinct product count")
        tvp = load_top_vendors_by_product_count(db_key, top_n_vendor)
        if _empty(tvp):
            st.info("No vendor/product data.")
        else:
            fig_tvp = px.bar(
                tvp.sort_values("n_products"),
                x="n_products",
                y="vendor_name",
                orientation="h",
                title=f"Top {top_n_vendor} vendors by product catalog size",
            )
            fig_tvp.update_layout(margin=dict(l=220, r=28, t=48, b=40))
            st.plotly_chart(fig_tvp, use_container_width=True)

        st.subheader("Version-range coverage")
        vrc = load_version_range_coverage(db_key)
        ap_total = vrc.get("ap_total", 0)
        if ap_total == 0:
            st.info("No affected_product rows.")
        else:
            cov_share = (vrc["ap_with_vr"] / ap_total) if ap_total else 0.0
            cv1, cv2 = st.columns(2)
            cv1.metric("affected_product rows", f"{ap_total:,}")
            cv2.metric("with version_range", f"{vrc['ap_with_vr']:,}", f"{cov_share * 100:.1f}%")
            fig_vrc = px.pie(
                pd.DataFrame(
                    {
                        "state": ["with version_range", "without"],
                        "n": [vrc["ap_with_vr"], vrc["ap_without_vr"]],
                    }
                ),
                values="n",
                names="state",
                hole=0.4,
                title="affected_product → version_range coverage",
                color="state",
                color_discrete_map={"with version_range": "#27ae60", "without": "#7f8c8d"},
            )
            st.plotly_chart(fig_vrc, use_container_width=True)

    # =====================================================================
    # References & sources
    # =====================================================================
    with tab_refs:
        st.subheader("References per CVE")
        rh = load_refs_per_cve_hist(db_key, sd_min, sd_max)
        if _empty(rh):
            st.info("No references in window.")
        else:
            cap = int(st.slider("Clamp references tail at", 5, 100, 25, step=5))
            rh_c = rh.copy()
            rh_c["bin"] = rh_c["refs"].clip(upper=cap)
            rh_b = rh_c.groupby("bin", as_index=False)["cves"].sum()
            rh_b["bin_label"] = rh_b["bin"].astype(str)
            rh_b.loc[rh_b["bin"] == cap, "bin_label"] = f"{cap}+"
            fig_rh = px.bar(
                rh_b,
                x="bin_label",
                y="cves",
                title=f"References-per-CVE distribution (clamped {cap}+)",
                labels={"bin_label": "refs per CVE", "cves": "CVE count"},
            )
            st.plotly_chart(fig_rh, use_container_width=True)

        st.subheader("Reference sources & trust tiers")
        rs = load_top_ref_sources(db_key, sd_min, sd_max, 15)
        rt = load_ref_trust_dist(db_key, sd_min, sd_max)
        rs1, rs2 = st.columns(2)
        if _empty(rs):
            rs1.info("No reference source data.")
        else:
            fig_rs = px.bar(
                rs.sort_values("n"),
                x="n",
                y="source",
                orientation="h",
                title="Top reference sources",
            )
            fig_rs.update_layout(margin=dict(l=160, r=28, t=48, b=36), yaxis_title=None)
            rs1.plotly_chart(fig_rs, use_container_width=True)
        if _empty(rt):
            rs2.info("No trust-tier data.")
        else:
            fig_rt = px.pie(rt, values="n", names="trust", hole=0.4, title="Reference trust tier")
            fig_rt.update_traces(textposition="inside", textinfo="percent+label")
            rs2.plotly_chart(fig_rt, use_container_width=True)

        st.subheader("Reference tags (top vocabulary)")
        rg = load_ref_tag_dist(db_key, sd_min, sd_max, 25)
        if _empty(rg):
            st.info("No reference_tag data.")
        else:
            fig_rg = px.bar(
                rg.sort_values("n"),
                x="n",
                y="tag",
                orientation="h",
                title="Most common reference_tag values",
            )
            fig_rg.update_layout(margin=dict(l=200, r=28, t=48, b=36), yaxis_title=None)
            st.plotly_chart(fig_rg, use_container_width=True)

        st.subheader("Patch-ish reference coverage by year")
        patch_yr = load_tag_coverage_yearly(db_key, sd_min, sd_max, _PATCH_TAGS)
        poc_yr = load_tag_coverage_yearly(db_key, sd_min, sd_max, _POC_TAGS)
        cov_a, cov_b = st.columns(2)
        if _empty(patch_yr):
            cov_a.info("No patch-tag coverage data.")
        else:
            patch_yr = patch_yr.copy()
            patch_yr["share_pct"] = patch_yr["share"] * 100.0
            fig_py = px.bar(
                patch_yr,
                x="year",
                y="share_pct",
                title=f"% of CVEs with at least one patch-ish ref ({', '.join(_PATCH_TAGS)})",
                hover_data=["n_total", "n_tagged"],
            )
            fig_py.update_layout(yaxis_title="% with patch-ish ref")
            cov_a.plotly_chart(fig_py, use_container_width=True)
        if _empty(poc_yr):
            cov_b.info("No PoC-tag coverage data.")
        else:
            poc_yr = poc_yr.copy()
            poc_yr["share_pct"] = poc_yr["share"] * 100.0
            fig_po = px.bar(
                poc_yr,
                x="year",
                y="share_pct",
                title=f"% of CVEs with at least one PoC-ish ref ({', '.join(_POC_TAGS)})",
                hover_data=["n_total", "n_tagged"],
                color_discrete_sequence=["#c0392b"],
            )
            fig_po.update_layout(yaxis_title="% with PoC-ish ref")
            cov_b.plotly_chart(fig_po, use_container_width=True)

    # =====================================================================
    # Threat intel
    # =====================================================================
    with tab_intel:
        st.markdown(
            "Threat-intel rows live in ``intel_string_list`` keyed by ``kind`` "
            "(``actor``, ``malware``, ``campaign``, ``osv_package``). Tab is wired "
            "up so it'll come alive once the intel providers start populating data."
        )
        ik = load_intel_kind_dist(db_key, sd_min, sd_max)
        if _empty(ik):
            st.info(
                "``intel_string_list`` is currently empty in the filter window. "
                "Once the OSV/actor/malware ingestion lands, charts here will fill in."
            )
        else:
            ic1, ic2 = st.columns(2)
            fig_ik = px.bar(ik, x="kind", y="n", title="Rows per intel kind")
            ic1.plotly_chart(fig_ik, use_container_width=True)
            fig_ikp = px.pie(ik, values="n", names="kind", hole=0.4, title="Intel kind share")
            ic2.plotly_chart(fig_ikp, use_container_width=True)

            kinds = ik["kind"].tolist()
            for kind in kinds:
                top_v = load_top_intel_values(db_key, sd_min, sd_max, kind, top_intel_n)
                if top_v.empty:
                    continue
                st.markdown(f"#### Top ``{kind}`` values")
                fig_tv = px.bar(
                    top_v.sort_values("n"),
                    x="n",
                    y="value",
                    orientation="h",
                    title=f"Top {top_intel_n} ``{kind}``",
                )
                fig_tv.update_layout(margin=dict(l=240, r=28, t=48, b=36), yaxis_title=None)
                st.plotly_chart(fig_tv, use_container_width=True)

    # =====================================================================
    # Lifecycle & latency
    # =====================================================================
    with tab_lifecycle:
        st.subheader("``published`` → ``modified`` lag")
        lag1 = load_published_modified_lag(db_key, sd_min, sd_max)
        if lag1.empty:
            st.info("No lag data.")
        else:
            cap_pm = int(st.slider("Clamp p→m lag at (days)", 30, 5000, 1825, step=30))
            lag1c = lag1.clip(lower=0, upper=cap_pm)
            fig_lag1 = px.histogram(
                lag1c,
                nbins=60,
                title=f"Days from publication to last modification (clamped {cap_pm}d)",
                labels={"value": "days"},
            )
            fig_lag1.update_layout(showlegend=False)
            st.plotly_chart(fig_lag1, use_container_width=True)

        st.subheader("``discovered`` → ``published`` lag")
        lag2 = load_discovered_published_lag(db_key, sd_min, sd_max)
        if lag2.empty:
            st.info("No discovered data set.")
        else:
            lag2c = lag2.clip(lower=-365, upper=365 * 5)
            fig_lag2 = px.histogram(
                lag2c,
                nbins=60,
                title="Days from discovery to publication (clamped −1y..+5y)",
                labels={"value": "days"},
            )
            fig_lag2.update_layout(showlegend=False)
            st.plotly_chart(fig_lag2, use_container_width=True)

        st.subheader("NVD analysis status")
        vs = load_vuln_status_dist(db_key, sd_min, sd_max)
        if _empty(vs):
            st.info("No vuln_status data.")
        else:
            vc1, vc2 = st.columns(2)
            fig_vs = px.bar(vs, x="vuln_status", y="n", title="``cve.vuln_status`` distribution")
            fig_vs.update_layout(xaxis_title=None, yaxis_title="CVEs")
            vc1.plotly_chart(fig_vs, use_container_width=True)

            vsy = load_vuln_status_by_year(db_key, sd_min, sd_max)
            if not _empty(vsy):
                fig_vsy = px.bar(
                    vsy,
                    x="year",
                    y="n",
                    color="vuln_status",
                    barmode="stack",
                    title="vuln_status by publication year",
                )
                fig_vsy.update_layout(xaxis_title=None, yaxis_title="CVEs")
                vc2.plotly_chart(fig_vsy, use_container_width=True)

        st.subheader("Modification recency heatmap")
        mh = load_modification_recency_heatmap(db_key, sd_min, sd_max)
        if _empty(mh):
            st.info("No modification heatmap data.")
        else:
            wide_mh = mh.pivot_table(
                index="mod_year", columns="pub_year", values="n", fill_value=0
            ).sort_index()
            fig_mh = px.imshow(
                wide_mh,
                color_continuous_scale="Magma",
                aspect="auto",
                title="CVE counts by (modification year, publication year) — diag = first-touch",
                labels={"x": "Publication year", "y": "Modification year", "color": "CVEs"},
            )
            fig_mh.update_layout(margin=dict(l=80, r=40, t=48, b=80))
            st.plotly_chart(fig_mh, use_container_width=True)

    # =====================================================================
    # Pipeline health
    # =====================================================================
    with tab_health:
        st.subheader("``pipeline_run`` state")
        if pr_df is None or pr_df.empty:
            st.info("``pipeline_run`` is empty — no phase has completed yet.")
        else:
            disp = pr_df.copy()
            disp["last_completed_at"] = pd.to_datetime(
                disp["last_completed_at"], errors="coerce", utc=True
            )
            now_utc = pd.Timestamp.now(tz="UTC")
            disp["age_days"] = (
                (now_utc - disp["last_completed_at"]).dt.total_seconds() // 86400
            ).astype("Int64")
            st.dataframe(
                disp[["phase", "last_completed_at", "last_watermark", "age_days"]],
                use_container_width=True,
                hide_index=True,
            )

        st.subheader("Table row counts")
        rc = load_table_row_counts(db_key)
        if _empty(rc):
            st.info("No row-count data.")
        else:
            fig_rc = px.bar(
                rc.sort_values("n_rows"),
                x="n_rows",
                y="table",
                orientation="h",
                title="Rows per table (log scale)",
                log_x=True,
            )
            fig_rc.update_layout(margin=dict(l=160, r=28, t=48, b=36), yaxis_title=None)
            st.plotly_chart(fig_rc, use_container_width=True)

        st.subheader("Distinct dimensions")
        dc = load_distinct_dimension_counts(db_key)
        cols_dc = st.columns(6)
        cols_dc[0].metric("Vendors", f"{dc.get('vendors', 0):,}")
        cols_dc[1].metric("Products", f"{dc.get('products', 0):,}")
        cols_dc[2].metric("CWEs", f"{dc.get('cwes', 0):,}")
        cols_dc[3].metric("Tags", f"{dc.get('tags', 0):,}")
        cols_dc[4].metric("CNAs", f"{dc.get('cnas', 0):,}")
        cols_dc[5].metric("KEV listed", f"{dc.get('kev_listed', 0):,}")

        st.subheader("Coverage at a glance")
        cov_df = load_enrichment_coverage(db_key, sd_min, sd_max)
        if _empty(cov_df):
            st.info("No coverage data.")
        else:
            cov_df = cov_df.copy()
            cov_df["share_pct"] = (cov_df["share"] * 100.0).round(2)
            fig_cov2 = px.bar(
                cov_df.sort_values("share_pct"),
                x="share_pct",
                y="enrichment",
                orientation="h",
                title="% of filtered CVEs with each enrichment",
            )
            fig_cov2.update_layout(margin=dict(l=200, r=28, t=48, b=36), yaxis_title=None)
            fig_cov2.update_xaxes(range=[0, 100])
            st.plotly_chart(fig_cov2, use_container_width=True)


if __name__ == "__main__":
    main()
