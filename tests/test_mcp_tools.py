"""Hermetic tests for ``vulnify.mcp`` tool functions.

We call the decorated functions directly (FastMCP's ``@mcp.tool()`` returns
the original function unchanged after registering it) against a temp SQLite
DB seeded with a small CVE fixture set. No network, no streaming server.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from vulnify.constants import ExploitMaturity, Severity
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.cve import CVE
from vulnify.models.cvss import CVSS
from vulnify.models.cwe import CWE
from vulnify.models.exploit import ExploitInfo
from vulnify.models.kev import KEVStatus
from vulnify.models.threat_intel import ThreatIntel
from vulnify.models.vendor import Vendor

import vulnify.mcp as mcp_module


def _make_cve(
    cve_id: str,
    *,
    title: str,
    summary: str,
    published: datetime,
    cvss_score: float,
    severity: Severity,
    epss: float | None = None,
    kev_listed: bool = False,
    vendor_name: str = "ExampleCorp",
    cwe_id: str = "CWE-79",
) -> CVE:
    cve = CVE(
        cve_id=cve_id,
        title=title,
        cna=vendor_name,
        primary_vendor=Vendor(name=vendor_name),
        published=published,
        modified=published,
        summary=summary,
        technical_details=f"Technical details for {cve_id}",
        cwes=[CWE(cwe_id=cwe_id, name="Test", description="")],
        cvss_scores=[
            CVSS(
                version="3.1",
                score=cvss_score,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity=severity,
                attack_vector="NETWORK",
            )
        ],
        exploit=ExploitInfo(maturity=ExploitMaturity.NONE),
    )
    if kev_listed:
        cve.kev = KEVStatus(
            listed=True,
            date_added=published.date(),
            vulnerability_name=title,
            vendor_project=vendor_name,
            product_label="Widget",
            short_description=summary,
            required_action="Patch immediately.",
            source="CISA",
        )
    if epss is not None:
        cve.intel = ThreatIntel(epss_score=epss, epss_percentile=epss * 100)
    return cve


class McpToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(
            repo_root / "vulnify" / "db" / "schema.sql"
        )
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp.name)
        tmp.close()

        self.store = SqliteCveStore(self.db_path)
        self.store.upsert_cve(
            _make_cve(
                "CVE-2026-0001",
                title="Critical RCE in widgetd",
                summary="Remote code execution via crafted HTTP request to widgetd.",
                published=datetime(2026, 3, 15, tzinfo=timezone.utc),
                cvss_score=9.8,
                severity=Severity.CRITICAL,
                epss=0.94,
                kev_listed=True,
                vendor_name="ExampleCorp",
                cwe_id="CWE-787",
            )
        )
        self.store.upsert_cve(
            _make_cve(
                "CVE-2026-0002",
                title="XSS in admin console",
                summary="Reflected cross-site scripting on the legacy admin console.",
                published=datetime(2026, 4, 10, tzinfo=timezone.utc),
                cvss_score=6.1,
                severity=Severity.MEDIUM,
                epss=0.12,
                kev_listed=False,
                vendor_name="OtherCorp",
                cwe_id="CWE-79",
            )
        )
        self.store.connection.commit()

        # Inject our pre-built store so _get_store() doesn't re-open one
        # against an env-pointed path.
        mcp_module._store = self.store

    def tearDown(self) -> None:
        mcp_module._store = None
        self.store.close()
        self.db_path.unlink(missing_ok=True)

    def test_get_cve_returns_full_record(self) -> None:
        result = mcp_module.get_cve("CVE-2026-0001")
        self.assertIsNotNone(result)
        self.assertEqual(result["cve_id"], "CVE-2026-0001")
        self.assertEqual(result["title"], "Critical RCE in widgetd")
        self.assertEqual(len(result["cvss_scores"]), 1)
        self.assertEqual(result["cvss_scores"][0]["score"], 9.8)
        self.assertEqual(result["cvss_scores"][0]["severity"], "CRITICAL")
        self.assertTrue(result["kev"]["listed"])
        self.assertEqual(result["intel"]["epss_score"], 0.94)

    def test_get_cve_unknown_returns_none(self) -> None:
        self.assertIsNone(mcp_module.get_cve("CVE-1999-9999"))

    def test_get_cve_case_insensitive(self) -> None:
        self.assertIsNotNone(mcp_module.get_cve("cve-2026-0001"))

    def test_get_cve_strips_date_sentinels_for_unlisted_kev(self) -> None:
        # CVE-2026-0002 has no KEV listing — KEVStatus defaults to
        # ``date.min`` for date_added/due_date. Those should serialise to
        # ``None`` so agents don't read 0001-01-01 as a real date.
        result = mcp_module.get_cve("CVE-2026-0002")
        self.assertIsNotNone(result)
        self.assertFalse(result["kev"]["listed"])
        self.assertIsNone(result["kev"]["date_added"])
        self.assertIsNone(result["kev"]["due_date"])

    def test_search_cves_kev_only(self) -> None:
        rows = mcp_module.search_cves(kev_only=True)
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2026-0001"])
        self.assertTrue(rows[0]["kev_listed"])

    def test_search_cves_min_cvss_filters(self) -> None:
        rows = mcp_module.search_cves(min_cvss=9.0)
        self.assertEqual({r["cve_id"] for r in rows}, {"CVE-2026-0001"})

    def test_search_cves_vendor_filter(self) -> None:
        rows = mcp_module.search_cves(vendor="othercorp")
        self.assertEqual({r["cve_id"] for r in rows}, {"CVE-2026-0002"})

    def test_search_cves_cwe_filter(self) -> None:
        rows = mcp_module.search_cves(cwe="CWE-79")
        self.assertEqual({r["cve_id"] for r in rows}, {"CVE-2026-0002"})

    def test_search_cves_year_filter(self) -> None:
        rows = mcp_module.search_cves(year=2026, limit=10)
        self.assertEqual(len(rows), 2)

    def test_search_cves_limit_clamped(self) -> None:
        rows = mcp_module.search_cves(limit=10_000)
        self.assertLessEqual(len(rows), mcp_module.MCP_MAX_LIMIT)

    def test_list_kev(self) -> None:
        rows = mcp_module.list_kev()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cve_id"], "CVE-2026-0001")
        self.assertEqual(rows[0]["vendor_project"], "ExampleCorp")

    def test_list_kev_since(self) -> None:
        self.assertEqual(mcp_module.list_kev(since="2027-01-01"), [])

    def test_database_overview(self) -> None:
        overview = mcp_module.database_overview()
        self.assertEqual(overview["totals"]["cves"], 2)
        self.assertEqual(overview["totals"]["kev_listed"], 1)
        self.assertEqual(overview["totals"]["cves_with_epss"], 2)
        self.assertIn("min", overview["published_range"])

    def test_search_cves_text_finds_match(self) -> None:
        rows = mcp_module.search_cves_text("widgetd")
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2026-0001"])

    def test_search_cves_text_phrase(self) -> None:
        rows = mcp_module.search_cves_text('"admin console"')
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2026-0002"])

    def test_search_cves_text_no_match(self) -> None:
        self.assertEqual(mcp_module.search_cves_text("zzzznonexistentterm"), [])


class ExploitArtefactAndReferenceToolTests(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(
            repo_root / "vulnify" / "db" / "schema.sql"
        )
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp.name)
        tmp.close()

        self.store = SqliteCveStore(self.db_path)
        # CVE-2021-44228 carries artefacts + references; CVE-2021-0000 carries
        # neither (the empty-result path, valid against the slice-1 schema).
        for cid in ("CVE-2021-44228", "CVE-2021-0000"):
            self.store.upsert_cve(
                _make_cve(
                    cid,
                    title=f"Title {cid}",
                    summary=f"Summary {cid}",
                    published=datetime(2021, 12, 10, tzinfo=timezone.utc),
                    cvss_score=10.0,
                    severity=Severity.CRITICAL,
                )
            )
        conn = self.store.connection
        # Two artefacts for the held CVE; platform/published_date left NULL to
        # exercise the None round-trip.
        conn.execute(
            "INSERT INTO exploit_artefact (cve_id, source, stable_id, url, "
            "artefact_type, platform, published_date, confidence) "
            "VALUES (?, 'nuclei', 'CVE-2021-44228', 'https://t/log4j', "
            "'critical', NULL, NULL, 'exact')",
            ("CVE-2021-44228",),
        )
        conn.execute(
            "INSERT INTO exploit_artefact (cve_id, source, stable_id, url, "
            "artefact_type, platform, published_date, confidence) "
            "VALUES (?, 'exploitdb', 'EDB-50592', "
            "'https://www.exploit-db.com/exploits/50592', 'webapps', 'java', "
            "'2021-12-14', 'parsed')",
            ("CVE-2021-44228",),
        )
        # References: one tagged patch, one tagged exploit.
        conn.execute(
            "INSERT INTO reference (cve_id, url, source, title, trust) "
            "VALUES (?, 'https://vendor/patch', 'vendor', 'Fix', 'vendor')",
            ("CVE-2021-44228",),
        )
        patch_rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO reference_tag (reference_id, tag) VALUES (?, 'patch')",
            (patch_rid,),
        )
        conn.execute(
            "INSERT INTO reference (cve_id, url, source, title, trust) "
            "VALUES (?, 'https://poc/exploit', 'community', 'PoC', 'community')",
            ("CVE-2021-44228",),
        )
        poc_rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO reference_tag (reference_id, tag) VALUES (?, 'exploit')",
            (poc_rid,),
        )
        conn.commit()

        mcp_module._store = self.store

    def tearDown(self) -> None:
        mcp_module._store = None
        self.store.close()
        self.db_path.unlink(missing_ok=True)

    def test_exploits_for_populated(self) -> None:
        rows = mcp_module.exploits_for("CVE-2021-44228")
        self.assertEqual(len(rows), 2)
        by_source = {r["source"]: r for r in rows}
        self.assertEqual(set(by_source), {"nuclei", "exploitdb"})
        nuclei = by_source["nuclei"]
        for key in ("source", "stable_id", "url", "confidence"):
            self.assertIn(key, nuclei)
        self.assertEqual(nuclei["confidence"], "exact")
        self.assertEqual(by_source["exploitdb"]["confidence"], "parsed")

    def test_exploits_for_case_insensitive(self) -> None:
        self.assertEqual(len(mcp_module.exploits_for("cve-2021-44228")), 2)

    def test_exploits_for_empty_returns_list(self) -> None:
        self.assertEqual(mcp_module.exploits_for("CVE-2021-0000"), [])
        self.assertEqual(mcp_module.exploits_for("CVE-1999-9999"), [])

    def test_get_cve_includes_artefacts(self) -> None:
        result = mcp_module.get_cve("CVE-2021-44228")
        self.assertIsNotNone(result)
        self.assertIn("artefacts", result)
        self.assertEqual(
            result["artefacts"], mcp_module.exploits_for("CVE-2021-44228")
        )
        # NULL columns round-trip as None, not absent.
        nuclei = next(a for a in result["artefacts"] if a["source"] == "nuclei")
        self.assertIsNone(nuclei["platform"])
        self.assertIsNone(nuclei["published_date"])

    def test_get_cve_without_artefacts_has_empty_list(self) -> None:
        result = mcp_module.get_cve("CVE-2021-0000")
        self.assertIsNotNone(result)
        self.assertEqual(result["artefacts"], [])

    def test_references_for_tag_filter(self) -> None:
        rows = mcp_module.references_for("CVE-2021-44228", tag="patch")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["url"], "https://vendor/patch")
        self.assertIn("patch", rows[0]["tags"])

    def test_references_for_no_tag_returns_all(self) -> None:
        rows = mcp_module.references_for("CVE-2021-44228")
        self.assertEqual(
            {r["url"] for r in rows},
            {"https://vendor/patch", "https://poc/exploit"},
        )

    def test_references_for_unknown_or_no_match(self) -> None:
        self.assertEqual(mcp_module.references_for("CVE-1999-9999"), [])
        self.assertEqual(
            mcp_module.references_for("CVE-2021-44228", tag="nonesuch"), []
        )


if __name__ == "__main__":
    unittest.main()
