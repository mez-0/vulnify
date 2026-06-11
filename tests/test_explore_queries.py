"""Smoke tests for explore SQL helpers (no Streamlit runtime required)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd

import explore.data as ed


def _fixture_db(path: Path) -> Path:
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    conn.executescript((Path(__file__).resolve().parents[1] / "vulnify/db/schema.sql").read_text())

    conn.execute(
        """
        INSERT INTO cve (cve_id, title, summary, published, modified)
        VALUES ('CVE-2020-1000', '', '', '2020-03-10T12:00:00+00:00', '2020-03-15T12:00:00+00:00'),
               ('CVE-2020-2000', '', '', '2020-05-02T08:00:00+00:00', '2020-05-03T08:00:00+00:00'),
               ('CVE-2019-1', '', '', '2019-11-01T00:00:00+00:00', '2019-11-02T00:00:00+00:00')
        """
    )

    conn.execute(
        "INSERT INTO vendor (name, website, country) VALUES "
        "('AcmeCo', '', ''), ('WidgetInc', '', ''), ('', '', '')"
    )
    conn.execute(
        """
        INSERT INTO cve_vendor (cve_id, vendor_id, role) VALUES
        ('CVE-2020-1000', 1, 'primary'), ('CVE-2020-1000', 2, 'affected'),
        ('CVE-2020-2000', 1, 'primary'),
        ('CVE-2019-1', 2, 'primary'),
        ('CVE-2019-1', 3, 'affected')
        """
    )

    conn.execute(
        """
        INSERT INTO cvss (cve_id, version, score, vector, severity, metric_source, metric_type)
        VALUES ('CVE-2020-1000', '3.1', 9.8, '', 'CRITICAL', 'test', 'Primary'),
               ('CVE-2020-2000', '3.1', 4.0, '', 'MEDIUM', 'test', 'Primary')
        """
    )

    conn.execute(
        """
        INSERT INTO cwe (cwe_id, name) VALUES ('CWE-79', 'XSS'), ('CWE-89', 'SQLi')
        """
    )
    conn.execute(
        """
        INSERT INTO cve_cwe (cve_id, cwe_id) VALUES
        ('CVE-2020-1000', 'CWE-79'),
        ('CVE-2020-2000', 'CWE-89'),
        ('CVE-2019-1', 'CWE-79')
        """
    )

    conn.execute(
        """
        INSERT INTO intel (cve_id, epss_score, epss_percentile)
        VALUES ('CVE-2020-1000', 0.42, 0.9), ('CVE-2020-2000', 0.01, 0.1)
        """
    )

    conn.execute(
        """
        INSERT INTO kev (cve_id, listed, date_added) VALUES ('CVE-2020-1000', 1, '2021-04-01')
        """
    )

    conn.commit()
    conn.close()
    return path


def test_explore_queries_smoke(tmp_path: Path) -> None:
    ed.st.cache_data.clear()

    p = _fixture_db(tmp_path / "t.db")
    key = str(p.resolve())

    ov = ed.load_overview(key, None, None)
    assert ov["total_cves"] == 3
    assert ov["cve_in_filter"] == 3
    assert ov["cve_kev_listed"] == 1
    assert ov["distinct_vendors"] == 2

    top_named = ed.load_top_vendor_ids(key, None, None, 10)
    assert (top_named["vendor_name"].astype(str).str.strip() != "").all()

    pairs = ed.load_cooccurrence_pairs(key, None, None, top_k=5)
    assert not pairs.empty
    assert set(pairs.columns) == {"vendor_a", "vendor_b", "shared_cves"}

    pub = ed.load_publications_monthly(key, "2020-01-01", "2020-12-31")
    assert pub["n"].sum() == 2

    cy = ed.load_cvss_year_stats(key, None, None)
    assert not cy.empty
    assert "avg_max_cvss" in cy.columns

    h, _ = ed.cooccurrence_heatmap_df(pairs)
    assert isinstance(h, pd.DataFrame)
    assert h.shape[0] >= 1

    html = ed.build_pyvis_graph_html(pairs, ed.load_top_vendor_ids(key, None, None, 5))
    assert "vis-network" in html or "pyvis" in html.lower() or len(html) > 100
