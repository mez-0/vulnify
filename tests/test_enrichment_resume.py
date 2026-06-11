"""Tests for enrichment resume (pending CVE ID queries)."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from vulnify.db.cve_upsert import CveUpsertPolicy, intel_only_cve_upsert_registry
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.cve import CVE
from vulnify.models.vendor import Vendor
from vulnify.providers.enrichment_resume import (
    cve_ids_pending_epss,
    cve_ids_pending_nvd,
    cve_ids_pending_osv,
)


class EnrichmentResumeTests(unittest.TestCase):
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

    def test_pending_nvd_excludes_merged_rows(self) -> None:
        base = dict(
            title="t",
            cna="c",
            primary_vendor=Vendor(),
            published=datetime(2026, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2026, 1, 2, tzinfo=timezone.utc),
            discovered=datetime.min.replace(tzinfo=timezone.utc),
        )
        fresh = CVE(cve_id="CVE-2026-1001", **base)
        merged = CVE(
            cve_id="CVE-2026-1002",
            vuln_status="Analyzed",
            source_identifier="nvd",
            **base,
        )
        with SqliteCveStore(self.db_path) as store:
            store.init_schema()
            store.upsert_cve(fresh)
            store.upsert_cve(merged)
            pending, total = cve_ids_pending_nvd(store.connection)
        self.assertEqual(total, 2)
        self.assertEqual(pending, ["CVE-2026-1001"])

    def test_pending_epss_excludes_nonzero_intel(self) -> None:
        base = dict(
            title="t",
            cna="c",
            primary_vendor=Vendor(),
            published=datetime(2026, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2026, 1, 2, tzinfo=timezone.utc),
            discovered=datetime.min.replace(tzinfo=timezone.utc),
        )
        a = CVE(cve_id="CVE-2026-2001", **base)
        b = CVE(cve_id="CVE-2026-2002", **base)
        pol_full = CveUpsertPolicy()
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
            store.upsert_cve(a, policy=pol_full)
            store.upsert_cve(b, policy=pol_full)
            b2 = store.get_cve("CVE-2026-2002")
            assert b2 is not None
            b2.intel.epss_score = 0.01
            b2.intel.epss_percentile = 0.5
            store.upsert_cve(
                b2, policy=pol_intel, registry=intel_only_cve_upsert_registry()
            )
            pending, total = cve_ids_pending_epss(store.connection)
        self.assertEqual(total, 2)
        self.assertEqual(pending, ["CVE-2026-2001"])

    def test_pending_osv_excludes_rows_with_packages(self) -> None:
        base = dict(
            title="t",
            cna="c",
            primary_vendor=Vendor(),
            published=datetime(2026, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2026, 1, 2, tzinfo=timezone.utc),
            discovered=datetime.min.replace(tzinfo=timezone.utc),
        )
        a = CVE(cve_id="CVE-2026-3001", **base)
        b = CVE(cve_id="CVE-2026-3002", **base)
        pol_full = CveUpsertPolicy()
        pol_osv = CveUpsertPolicy(
            core_row=False,
            primary_vendor_edge=False,
            affected_products=False,
            affected_vendor_edges=False,
            cwes=False,
            cvss_scores=False,
            cpe_matches=False,
            exploit=False,
            kev=False,
            intel_scores=False,
            intel_string_lists=True,
            references=False,
            cve_tags=False,
        )
        with SqliteCveStore(self.db_path) as store:
            store.init_schema()
            store.upsert_cve(a, policy=pol_full)
            store.upsert_cve(b, policy=pol_full)
            b2 = store.get_cve("CVE-2026-3002")
            assert b2 is not None
            b2.intel.osv_packages.append("PyPI:foo")
            store.upsert_cve(
                b2, policy=pol_osv, registry=intel_only_cve_upsert_registry()
            )
            pending, total = cve_ids_pending_osv(store.connection)
        self.assertEqual(total, 2)
        self.assertEqual(pending, ["CVE-2026-3001"])

    def test_pending_osv_excludes_checked_rows_without_packages(self) -> None:
        # A CVE conclusively checked against OSV (200/404, no packages) gets an
        # ``osv_checked`` marker and must not be re-queried on the next run.
        base = dict(
            title="t",
            cna="c",
            primary_vendor=Vendor(),
            published=datetime(2026, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2026, 1, 2, tzinfo=timezone.utc),
            discovered=datetime.min.replace(tzinfo=timezone.utc),
        )
        a = CVE(cve_id="CVE-2026-4001", **base)
        b = CVE(cve_id="CVE-2026-4002", **base)
        with SqliteCveStore(self.db_path) as store:
            store.init_schema()
            store.upsert_cve(a, policy=CveUpsertPolicy())
            store.upsert_cve(b, policy=CveUpsertPolicy())
            store.connection.execute(
                "INSERT INTO intel_string_list (cve_id, kind, value) "
                "VALUES ('CVE-2026-4002', 'osv_checked', '1')"
            )
            store.connection.commit()
            pending, total = cve_ids_pending_osv(store.connection)
        self.assertEqual(total, 2)
        self.assertEqual(pending, ["CVE-2026-4001"])


if __name__ == "__main__":
    unittest.main()
