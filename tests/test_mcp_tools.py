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

import vulnify.db.vendor_index as mcp_module_vendor_index
from vulnify.db.vendor_index import rebuild_product_cpe_vendor

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


class VendorFilterTests(unittest.TestCase):
    """The vendor filter, against a scale model of the Aruba/ClearPass corpus.

    Reproduces the shape that made ``search_cves(vendor="aruba",
    product="clearpass")`` return zero rows for a product with 152 CVEs: three
    spellings of one product split across an empty placeholder vendor and HPE,
    plus a genuine but unrelated vendor called ``Aruba`` (the Italian hosting
    company) that a naive substring filter matches instead.

    Seeds ``cpe_match`` and then runs the real
    :func:`~vulnify.db.vendor_index.rebuild_product_cpe_vendor`, so the index
    build is under test too rather than hand-stubbed.
    """

    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(
            repo_root / "vulnify" / "db" / "schema.sql"
        )
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp.name)
        tmp.close()

        self.store = SqliteCveStore(self.db_path)
        conn = self.store.connection

        self.vendors = {
            name: self._vendor(name)
            for name in ("", "Hewlett Packard Enterprise", "Aruba.it", "Dell")
        }
        # Product name carries the vendor token; its vendor is the placeholder.
        self.p_named = self._product("Aruba ClearPass Policy Manager", "")
        # Neither the product name nor its vendor names Aruba — CPE only.
        self.p_cpe_only = self._product("ClearPass Policy Manager", "")
        # Real vendor, but not one whose name contains "aruba".
        self.p_hpe = self._product(
            "ClearPass Policy Manager (CPPM)", "Hewlett Packard Enterprise"
        )
        self.p_hosting = self._product("Hosting Control Panel", "Aruba.it")
        self.p_stray = self._product("iDRAC Service Module", "Dell")
        self.p_placeholder = self._product("n/a", "")

        # One CVE per branch of the vendor predicate.
        self._cve("CVE-2020-0001", products=[self.p_named])
        self._cve(
            "CVE-2020-0002",
            products=[self.p_cpe_only],
            cpes=[
                "cpe:2.3:a:arubanetworks:clearpass_policy_manager:6.9:*:*:*:*:*:*:*",
                "cpe:2.3:a:arubanetworks:clearpass_policy_manager:6.8:*:*:*:*:*:*:*",
            ],
        )
        self._cve(
            "CVE-2020-0003",
            products=[self.p_hpe],
            vendors=[("Hewlett Packard Enterprise", "primary")],
            cpes=[
                "cpe:2.3:a:arubanetworks:clearpass_policy_manager:6.7:*:*:*:*:*:*:*",
                "cpe:2.3:a:arubanetworks:clearpass_policy_manager:6.6:*:*:*:*:*:*:*",
            ],
        )
        # The name collision: a real vendor called Aruba, unrelated product.
        self._cve(
            "CVE-2020-0004",
            products=[self.p_hosting],
            vendors=[("Aruba.it", "primary")],
        )
        # A lone stray CPE occurrence must not make this a ClearPass/Aruba CVE.
        self._cve(
            "CVE-2020-0005",
            products=[self.p_stray],
            vendors=[("Dell", "primary")],
            cpes=["cpe:2.3:a:arubanetworks:clearpass_policy_manager:6.5:*:*:*:*:*:*:*"],
        )
        # The cvelistV5 placeholder product: shared by everything, so its CPE
        # evidence names far too many vendors to mean anything.
        self._cve(
            "CVE-2020-0006",
            products=[self.p_placeholder],
            cpes=[
                f"cpe:2.3:a:vendor{i}:thing:1.0:*:*:*:*:*:*:*"
                for i in range(mcp_module_vendor_index.MAX_SLUGS_PER_PRODUCT + 4)
            ]
            + ["cpe:2.3:a:arubanetworks:clearpass_policy_manager:1:*:*:*:*:*:*:*"],
        )

        rebuild_product_cpe_vendor(conn)
        conn.commit()
        mcp_module._store = self.store

    def tearDown(self) -> None:
        mcp_module._store = None
        self.store.close()
        self.db_path.unlink(missing_ok=True)

    # -- fixture helpers ---------------------------------------------------

    def _vendor(self, name: str) -> int:
        cur = self.store.connection.execute(
            "INSERT INTO vendor (name, website, country) VALUES (?, '', '')", (name,)
        )
        return int(cur.lastrowid)

    def _product(self, name: str, vendor_name: str) -> int:
        cur = self.store.connection.execute(
            "INSERT INTO product (name, vendor_id, product_type, family, component) "
            "VALUES (?, ?, 'application', '', '')",
            (name, self.vendors[vendor_name]),
        )
        return int(cur.lastrowid)

    def _cve(
        self,
        cve_id: str,
        *,
        products: list[int],
        vendors: list[tuple[str, str]] | None = None,
        cpes: list[str] | None = None,
    ) -> None:
        conn = self.store.connection
        conn.execute(
            "INSERT INTO cve (cve_id, title, summary, published, modified) "
            "VALUES (?, ?, '', '2020-06-01T00:00:00+00:00', "
            "'2020-06-01T00:00:00+00:00')",
            (cve_id, f"Title {cve_id}"),
        )
        for product_id in products:
            conn.execute(
                "INSERT INTO affected_product (cve_id, product_id, affected) "
                "VALUES (?, ?, 1)",
                (cve_id, product_id),
            )
        for vendor_name, role in vendors or []:
            conn.execute(
                "INSERT INTO cve_vendor (cve_id, vendor_id, role) VALUES (?, ?, ?)",
                (cve_id, self.vendors[vendor_name], role),
            )
        for criteria in cpes or []:
            conn.execute(
                "INSERT INTO cpe_match (cve_id, criteria, match_criteria_id, "
                "vulnerable) VALUES (?, ?, NULL, 1)",
                (cve_id, criteria),
            )

    @staticmethod
    def _ids(rows: list[dict]) -> set[str]:
        return {r["cve_id"] for r in rows}

    # -- the reported bug --------------------------------------------------

    def test_vendor_plus_product_finds_every_spelling(self) -> None:
        """The regression test for the filed bug: this used to return zero."""
        found = self._ids(
            mcp_module.search_cves(vendor="aruba", product="clearpass", limit=100)
        )
        self.assertEqual(found, {"CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"})

    # -- each branch must rescue a CVE the others cannot -------------------

    def test_branch_product_name(self) -> None:
        self.assertIn("CVE-2020-0001", self._ids(mcp_module.search_cves(vendor="aruba")))

    def test_branch_cpe_slug(self) -> None:
        """Placeholder vendor, product name without the vendor token."""
        self.assertIn("CVE-2020-0002", self._ids(mcp_module.search_cves(vendor="aruba")))

    def test_branch_product_ownership(self) -> None:
        found = self._ids(mcp_module.search_cves(vendor="hewlett"))
        self.assertIn("CVE-2020-0003", found)

    def test_branch_cve_vendor_edge_still_works(self) -> None:
        """The original behaviour is preserved as one branch among four."""
        self.assertIn("CVE-2020-0004", self._ids(mcp_module.search_cves(vendor="aruba.it")))

    # -- correlation -------------------------------------------------------

    def test_vendor_and_product_must_describe_the_same_product(self) -> None:
        """Dell owns no ClearPass product, so this must be empty.

        The old independent joins matched whenever a CVE had *some* vendor edge
        and, separately, *some* matching product.
        """
        self.assertEqual(
            mcp_module.search_cves(vendor="dell", product="clearpass", limit=100), []
        )

    def test_unrelated_vendor_of_same_name_is_not_a_clearpass_hit(self) -> None:
        found = self._ids(
            mcp_module.search_cves(vendor="aruba", product="clearpass", limit=100)
        )
        self.assertNotIn("CVE-2020-0004", found)

    # -- evidence quality guards ------------------------------------------

    def test_single_cpe_occurrence_is_not_vendor_evidence(self) -> None:
        """One stray CPE must not re-badge Dell's product as Aruba's."""
        self.assertNotIn("CVE-2020-0005", self._ids(mcp_module.search_cves(vendor="aruba")))

    def test_placeholder_product_is_excluded_from_the_index(self) -> None:
        """A product naming too many CPE vendors would match every vendor term.

        Without this guard the shared ``n/a`` product made a search for ``aruba``
        return 144,237 CVEs against the real corpus instead of a few hundred.
        """
        rows = self.store.connection.execute(
            "SELECT COUNT(*) FROM product_cpe_vendor WHERE product_id = ?",
            (self.p_placeholder,),
        ).fetchone()[0]
        self.assertEqual(rows, 0)
        self.assertNotIn("CVE-2020-0006", self._ids(mcp_module.search_cves(vendor="aruba")))

    def test_rebuild_is_idempotent(self) -> None:
        before = self.store.connection.execute(
            "SELECT product_id, slug, n FROM product_cpe_vendor ORDER BY 1, 2"
        ).fetchall()
        rebuild_product_cpe_vendor(self.store.connection)
        after = self.store.connection.execute(
            "SELECT product_id, slug, n FROM product_cpe_vendor ORDER BY 1, 2"
        ).fetchall()
        self.assertEqual([tuple(r) for r in before], [tuple(r) for r in after])

    # -- list_vendors ------------------------------------------------------

    def test_list_vendors_excludes_the_placeholder(self) -> None:
        names = {r["name"] for r in mcp_module.list_vendors(limit=100)}
        self.assertNotIn("", names)
        self.assertIn("Hewlett Packard Enterprise", names)

    def test_list_vendors_disambiguates_the_collision(self) -> None:
        """The affordance an agent needs to spot the wrong-company match."""
        rows = mcp_module.list_vendors(query="aruba")
        self.assertEqual([r["name"] for r in rows], ["Aruba.it"])
        self.assertEqual(rows[0]["cve_count"], 1)

    def test_list_vendors_reports_cpe_slugs(self) -> None:
        rows = mcp_module.list_vendors(query="hewlett")
        self.assertEqual(rows[0]["name"], "Hewlett Packard Enterprise")
        self.assertIn("arubanetworks", rows[0]["cpe_slugs"])

    def test_list_vendors_limit_clamped(self) -> None:
        self.assertLessEqual(
            len(mcp_module.list_vendors(limit=10_000)), mcp_module.MCP_MAX_LIMIT
        )


if __name__ == "__main__":
    unittest.main()
