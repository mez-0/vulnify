"""Tests for affected_product/version_range/product dedup behavior."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from vulnify.constants import ProductType
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.affected import AffectedProduct
from vulnify.models.cve import CVE
from vulnify.models.vendor import Product, Vendor
from vulnify.models.version import VersionRange


def _base_cve_kwargs() -> dict:
    return dict(
        title="t",
        cna="c",
        primary_vendor=Vendor(name="acme"),
        published=datetime(2026, 1, 1, tzinfo=timezone.utc),
        modified=datetime(2026, 1, 2, tzinfo=timezone.utc),
        discovered=datetime.min.replace(tzinfo=timezone.utc),
    )


class DedupTests(unittest.TestCase):
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

    def test_duplicate_affected_products_collapse_within_one_upsert(self) -> None:
        vendor = Vendor(name="acme")
        product = Product(
            name="widget",
            vendor=vendor,
            product_type=ProductType.APPLICATION,
            component="",
        )
        ap = AffectedProduct(
            product=product,
            versions=[VersionRange(start_including="1.0", end_excluding="2.0")],
            affected=True,
        )
        cve = CVE(
            cve_id="CVE-2026-DEDUP1",
            affected_products=[ap, ap, ap],
            **_base_cve_kwargs(),
        )
        with SqliteCveStore(self.db_path) as store:
            store.upsert_cve(cve)
            cur = store.connection.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM affected_product WHERE cve_id = ?",
                (cve.cve_id,),
            )
            ap_count = int(cur.fetchone()[0])
            cur.execute(
                """
                SELECT COUNT(*) FROM version_range vr
                JOIN affected_product ap ON ap.id = vr.affected_product_id
                WHERE ap.cve_id = ?
                """,
                (cve.cve_id,),
            )
            vr_count = int(cur.fetchone()[0])
        self.assertEqual(ap_count, 1)
        self.assertEqual(vr_count, 1)

    def test_case_insensitive_product_dedup(self) -> None:
        vendor = Vendor(name="acme")
        # Same product but different casing on name.
        prod_upper = Product(
            name="Linux Kernel",
            vendor=vendor,
            product_type=ProductType.APPLICATION,
            component="",
        )
        prod_lower = Product(
            name="linux kernel",
            vendor=vendor,
            product_type=ProductType.APPLICATION,
            component="",
        )
        cve_a = CVE(
            cve_id="CVE-2026-CASE1",
            affected_products=[
                AffectedProduct(product=prod_upper, versions=[], affected=True)
            ],
            **_base_cve_kwargs(),
        )
        cve_b = CVE(
            cve_id="CVE-2026-CASE2",
            affected_products=[
                AffectedProduct(product=prod_lower, versions=[], affected=True)
            ],
            **_base_cve_kwargs(),
        )
        with SqliteCveStore(self.db_path) as store:
            store.upsert_cve(cve_a)
            store.upsert_cve(cve_b)
            cur = store.connection.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM product WHERE lower(trim(name)) = 'linux kernel'"
            )
            product_count = int(cur.fetchone()[0])
        self.assertEqual(product_count, 1)

    def test_affected_product_unique_constraint_present(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            cur = store.connection.cursor()
            cur.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type='index' AND name='affected_product_unique'"
            )
            self.assertIsNotNone(cur.fetchone())


if __name__ == "__main__":
    unittest.main()
