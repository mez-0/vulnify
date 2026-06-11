"""Tests for NVD/CISA-shaped fields, CPE rows, and intel-only upserts."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

from vulnify.constants import Severity
from vulnify.db.cve_upsert import CveUpsertPolicy, intel_only_cve_upsert_registry
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.cpe import CpeMatch
from vulnify.models.cve import CVE
from vulnify.models.cvss import CVSS
from vulnify.models.kev import KEVStatus
from vulnify.models.vendor import Vendor


class EnrichmentSqliteTests(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(
            repo_root / "vulnify" / "db" / "schema.sql"
        )
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp.name)
        tmp.close()

    def tearDown(self) -> None:
        self.db_path.unlink(missing_ok=True)

    def test_cvss_lineage_kev_extended_cpe_roundtrip(self) -> None:
        cve = CVE(
            cve_id="CVE-2026-9999",
            title="t",
            cna="c",
            primary_vendor=Vendor(name="V"),
            published=datetime(2026, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2026, 1, 2, tzinfo=timezone.utc),
            discovered=datetime.min.replace(tzinfo=timezone.utc),
            vuln_status="Analyzed",
            source_identifier="src@test",
            cvss_scores=[
                CVSS(
                    version="3.1",
                    score=9.0,
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    severity=Severity.CRITICAL,
                    metric_source="nvd@nist.gov",
                    metric_type="Primary",
                    exploitability_score=3.9,
                    impact_score=5.9,
                )
            ],
            cpe_matches=[
                CpeMatch(
                    criteria="cpe:2.3:o:a:b:1:*:*:*:*:*:*:*",
                    match_criteria_id="mid",
                    vulnerable=True,
                )
            ],
            kev=KEVStatus(
                listed=True,
                date_added=date(2026, 1, 10),
                due_date=date(2026, 1, 20),
                notes="n",
                vulnerability_name="vn",
                required_action="patch",
                vendor_project="VP",
                product_label="PL",
                short_description="sd",
                source="cisa",
            ),
        )
        with SqliteCveStore(self.db_path) as store:
            store.init_schema()
            store.upsert_cve(cve)
            loaded = store.get_cve("CVE-2026-9999")
        assert loaded is not None
        self.assertEqual(loaded.vuln_status, "Analyzed")
        self.assertEqual(loaded.source_identifier, "src@test")
        self.assertEqual(loaded.cvss_scores[0].metric_type, "Primary")
        self.assertAlmostEqual(loaded.cvss_scores[0].exploitability_score, 3.9)
        self.assertEqual(loaded.cpe_matches[0].criteria, "cpe:2.3:o:a:b:1:*:*:*:*:*:*:*")
        self.assertEqual(loaded.kev.source, "cisa")
        self.assertEqual(loaded.kev.required_action, "patch")

    def test_intel_only_upsert_updates_epss(self) -> None:
        cve = CVE(
            cve_id="CVE-2026-8888",
            title="x",
            cna="y",
            primary_vendor=Vendor(),
            published=datetime(2026, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2026, 1, 2, tzinfo=timezone.utc),
            discovered=datetime.min.replace(tzinfo=timezone.utc),
        )
        policy_full = CveUpsertPolicy()
        pol_intel = CveUpsertPolicy(
            core_row=False,
            primary_vendor_edge=False,
            affected_products=False,
            affected_vendor_edges=False,
            cwes=False,
            cvss_scores=False,
            cpe_matches=False,
            exploit=False,
            kev=False,
            intel_scores=True,
            intel_string_lists=False,
            references=False,
            cve_tags=False,
        )
        with SqliteCveStore(self.db_path) as store:
            store.init_schema()
            store.upsert_cve(cve, policy=policy_full)
            loaded = store.get_cve("CVE-2026-8888")
            assert loaded is not None
            loaded.intel.epss_score = 0.42
            loaded.intel.epss_percentile = 0.9
            store.upsert_cve(
                loaded, policy=pol_intel, registry=intel_only_cve_upsert_registry()
            )
            again = store.get_cve("CVE-2026-8888")
        assert again is not None
        self.assertAlmostEqual(again.intel.epss_score, 0.42)
        self.assertAlmostEqual(again.intel.epss_percentile, 0.9)
        self.assertEqual(again.title, "x")


if __name__ == "__main__":
    unittest.main()
