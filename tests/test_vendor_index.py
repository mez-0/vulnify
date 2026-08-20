"""Hermetic tests for the derived vendor index and the sentinel repoint.

Temp SQLite DB + raw fixture rows, no network and no mocking library.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.db.vendor_index import (
    DOMINANCE_THRESHOLD,
    build_vendor_index,
    rebuild_product_cpe_vendor,
    repoint_sentinel_products,
)
from vulnify.models.vendor import Product, Vendor


class VendorIndexTestCase(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(
            repo_root / "vulnify" / "db" / "schema.sql"
        )
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp.name)
        tmp.close()
        self.store = SqliteCveStore(self.db_path)
        self.conn = self.store.connection

    def tearDown(self) -> None:
        self.store.close()
        self.db_path.unlink(missing_ok=True)

    # -- helpers -----------------------------------------------------------

    def _vendor(self, name: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO vendor (name, website, country) VALUES (?, '', '')", (name,)
        )
        return int(cur.lastrowid)

    def _product(self, name: str, vendor_id: int, component: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO product (name, vendor_id, product_type, family, component) "
            "VALUES (?, ?, 'application', '', ?)",
            (name, vendor_id, component),
        )
        return int(cur.lastrowid)

    def _cve(self, cve_id: str, product_id: int, cpes: list[str]) -> None:
        self.conn.execute(
            "INSERT INTO cve (cve_id, title, summary, published, modified) "
            "VALUES (?, '', '', '2020-01-01T00:00:00+00:00', "
            "'2020-01-01T00:00:00+00:00')",
            (cve_id,),
        )
        self.conn.execute(
            "INSERT INTO affected_product (cve_id, product_id, affected) VALUES (?, ?, 1)",
            (cve_id, product_id),
        )
        for criteria in cpes:
            self.conn.execute(
                "INSERT INTO cpe_match (cve_id, criteria, match_criteria_id, vulnerable) "
                "VALUES (?, ?, NULL, 1)",
                (cve_id, criteria),
            )

    def _vendor_of(self, product_id: int) -> str:
        row = self.conn.execute(
            "SELECT v.name FROM product p JOIN vendor v ON v.vendor_id = p.vendor_id "
            "WHERE p.product_id = ?",
            (product_id,),
        ).fetchone()
        return "" if row is None else str(row[0])

    @staticmethod
    def _cpe(vendor_slug: str, product: str, version: str) -> str:
        return f"cpe:2.3:a:{vendor_slug}:{product}:{version}:*:*:*:*:*:*:*"


class RepointTests(VendorIndexTestCase):
    def test_unanimous_evidence_repoints_the_product(self) -> None:
        sentinel = self._vendor("")
        self._vendor("arubanetworks")
        product = self._product("ClearPass Policy Manager", sentinel)
        self._cve(
            "CVE-2020-0001",
            product,
            [self._cpe("arubanetworks", "clearpass", v) for v in ("6.9", "6.8")],
        )
        rebuild_product_cpe_vendor(self.conn)

        self.assertEqual(repoint_sentinel_products(self.conn), 1)
        self.assertEqual(self._vendor_of(product), "arubanetworks")

    def test_underscored_slug_matches_a_spaced_vendor_name(self) -> None:
        """CPE writes ``red_hat``; the vendor row says ``Red Hat``."""
        sentinel = self._vendor("")
        self._vendor("Red Hat")
        product = self._product("kernel-rt", sentinel)
        self._cve(
            "CVE-2020-0002",
            product,
            [self._cpe("red_hat", "enterprise_linux", v) for v in ("8", "9")],
        )
        rebuild_product_cpe_vendor(self.conn)

        self.assertEqual(repoint_sentinel_products(self.conn), 1)
        self.assertEqual(self._vendor_of(product), "Red Hat")

    def test_ambiguous_evidence_is_left_alone(self) -> None:
        """Below the dominance bar we under-claim rather than guess.

        This is what keeps the shared ``n/a`` placeholder product — whose top CPE
        vendor holds only ~7% of its evidence — from being assigned to Linux.
        """
        sentinel = self._vendor("")
        self._vendor("linux")
        self._vendor("netapp")
        product = self._product("kernel", sentinel)
        self._cve("CVE-2020-0003", product, [self._cpe("linux", "kernel", "5.1")] * 1)
        self._cve(
            "CVE-2020-0004",
            product,
            [self._cpe("linux", "kernel", "5.2"), self._cpe("netapp", "ontap", "9")],
        )
        self._cve(
            "CVE-2020-0005",
            product,
            [self._cpe("netapp", "ontap", "9.1"), self._cpe("netapp", "ontap", "9.2")],
        )
        rebuild_product_cpe_vendor(self.conn)

        best = self.conn.execute(
            "SELECT MAX(n) * 1.0 / SUM(n) FROM product_cpe_vendor WHERE product_id = ?",
            (product,),
        ).fetchone()[0]
        self.assertLess(best, DOMINANCE_THRESHOLD)
        self.assertEqual(repoint_sentinel_products(self.conn), 0)
        self.assertEqual(self._vendor_of(product), "")

    def test_slug_with_no_existing_vendor_mints_nothing(self) -> None:
        """CPE slugs like ``404like_project`` must not become vendor rows."""
        sentinel = self._vendor("")
        product = self._product("404like", sentinel)
        self._cve(
            "CVE-2020-0006",
            product,
            [self._cpe("404like_project", "404like", v) for v in ("1.0", "1.1")],
        )
        rebuild_product_cpe_vendor(self.conn)

        before = self.conn.execute("SELECT COUNT(*) FROM vendor").fetchone()[0]
        self.assertEqual(repoint_sentinel_products(self.conn), 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vendor").fetchone()[0], before)
        self.assertEqual(self._vendor_of(product), "")

    def test_repoint_merges_into_an_existing_twin(self) -> None:
        """Where the destination product already exists, merge instead of moving."""
        sentinel = self._vendor("")
        hpe = self._vendor("arubanetworks")
        loser = self._product("ClearPass Policy Manager", sentinel)
        keeper = self._product("ClearPass Policy Manager", hpe)
        self._cve(
            "CVE-2020-0007",
            loser,
            [self._cpe("arubanetworks", "clearpass", v) for v in ("6.9", "6.8")],
        )
        # Same CVE also lists the keeper product — the collision case for
        # affected_product_unique (cve_id, product_id).
        self.conn.execute(
            "INSERT INTO affected_product (cve_id, product_id, affected) VALUES (?, ?, 1)",
            ("CVE-2020-0007", keeper),
        )
        self._cve("CVE-2020-0008", loser, [])
        rebuild_product_cpe_vendor(self.conn)

        self.assertEqual(repoint_sentinel_products(self.conn), 1)
        # Loser row is gone, and nothing references it.
        self.assertIsNone(
            self.conn.execute(
                "SELECT 1 FROM product WHERE product_id = ?", (loser,)
            ).fetchone()
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM affected_product WHERE product_id = ?", (loser,)
            ).fetchone()[0],
            0,
        )
        # Both CVEs now hang off the keeper, exactly once each.
        rows = self.conn.execute(
            "SELECT cve_id, COUNT(*) FROM affected_product WHERE product_id = ? "
            "GROUP BY cve_id ORDER BY cve_id",
            (keeper,),
        ).fetchall()
        self.assertEqual(
            [(r[0], r[1]) for r in rows],
            [("CVE-2020-0007", 1), ("CVE-2020-0008", 1)],
        )

    def test_reingest_after_repoint_does_not_accumulate_duplicates(self) -> None:
        """The trap: ``ensure_product`` keys on ``vendor_id``.

        After a product is moved off the placeholder vendor, the next gather
        still reads ``vendor: n/a`` from cvelistV5, so the lookup misses and
        inserts a *fresh* row under the placeholder. If the phase only ever
        ``UPDATE``-d, that would add one duplicate per gather forever. It merges
        instead, so the index re-converges on each run.
        """
        sentinel = self._vendor("")
        self._vendor("arubanetworks")
        product = self._product("ClearPass Policy Manager", sentinel)
        cpes = [self._cpe("arubanetworks", "clearpass", v) for v in ("6.9", "6.8")]
        self._cve("CVE-2020-0009", product, cpes)

        build_vendor_index(self.conn)
        self.assertEqual(self._vendor_of(product), "arubanetworks")

        # Simulate the next gather re-ingesting the same cvelistV5 record: the
        # real write path, with the vendor still absent upstream.
        cur = self.conn.cursor()
        vid = self.store.ensure_vendor(cur, Vendor())
        self.assertEqual(vid, sentinel)
        dup = self.store.ensure_product(
            cur, Product(name="ClearPass Policy Manager", vendor=Vendor()), vid
        )
        self.assertNotEqual(dup, product)  # a genuine duplicate now exists
        self._cve("CVE-2020-0010", dup, cpes)

        # The phase runs again and cleans up after the re-ingest.
        build_vendor_index(self.conn)

        rows = self.conn.execute(
            "SELECT p.product_id, v.name FROM product p "
            "JOIN vendor v ON v.vendor_id = p.vendor_id "
            "WHERE lower(p.name) = 'clearpass policy manager'"
        ).fetchall()
        self.assertEqual(len(rows), 1, f"expected one product row, got {rows}")
        self.assertEqual(str(rows[0][1]), "arubanetworks")

        # Both CVEs survived the merge.
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(DISTINCT cve_id) FROM affected_product WHERE product_id = ?",
                (int(rows[0][0]),),
            ).fetchone()[0],
            2,
        )

    def test_build_is_idempotent(self) -> None:
        sentinel = self._vendor("")
        self._vendor("arubanetworks")
        product = self._product("ClearPass Policy Manager", sentinel)
        self._cve(
            "CVE-2020-0011",
            product,
            [self._cpe("arubanetworks", "clearpass", v) for v in ("6.9", "6.8")],
        )

        first = build_vendor_index(self.conn)
        second = build_vendor_index(self.conn)
        self.assertEqual(first[0], second[0])
        self.assertEqual(second[1], 0, "nothing left to repoint on the second pass")
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM product").fetchone()[0], 1
        )

    def test_no_sentinel_vendor_is_a_no_op(self) -> None:
        real = self._vendor("arubanetworks")
        product = self._product("ClearPass", real)
        self._cve("CVE-2020-0012", product, [self._cpe("arubanetworks", "clearpass", "1")])
        rebuild_product_cpe_vendor(self.conn)
        self.assertEqual(repoint_sentinel_products(self.conn), 0)


class MigrationHealTests(unittest.TestCase):
    """A shipped release DB must gain the index on first open, without a gather."""

    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        self.schema_path = repo_root / "vulnify" / "db" / "schema.sql"
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(self.schema_path)
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp.name)
        tmp.close()

    def tearDown(self) -> None:
        self.db_path.unlink(missing_ok=True)

    def test_migration_builds_the_index_on_a_legacy_db(self) -> None:
        from vulnify.db.migrate import apply_sqlite_migrations

        # Bootstrap the schema, then un-apply the new table to look "legacy".
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(self.schema_path.read_text(encoding="utf-8"))
        conn.execute("DROP TABLE IF EXISTS product_cpe_vendor")
        conn.executescript(
            """
            INSERT INTO vendor (vendor_id, name) VALUES (1, ''), (2, 'arubanetworks');
            INSERT INTO product (product_id, name, vendor_id, component)
                VALUES (1, 'ClearPass Policy Manager', 1, '');
            INSERT INTO cve (cve_id, title, summary, published, modified) VALUES
                ('CVE-2020-7110', '', '', '2020-06-01T00:00:00+00:00',
                 '2020-06-01T00:00:00+00:00');
            INSERT INTO affected_product (cve_id, product_id, affected)
                VALUES ('CVE-2020-7110', 1, 1);
            INSERT INTO cpe_match (cve_id, criteria, vulnerable) VALUES
                ('CVE-2020-7110',
                 'cpe:2.3:a:arubanetworks:clearpass_policy_manager:6.9:*:*:*:*:*:*:*', 1),
                ('CVE-2020-7110',
                 'cpe:2.3:a:arubanetworks:clearpass_policy_manager:6.8:*:*:*:*:*:*:*', 1);
            """
        )
        conn.commit()

        apply_sqlite_migrations(conn)
        conn.commit()

        self.assertEqual(
            conn.execute(
                "SELECT slug FROM product_cpe_vendor WHERE product_id = 1"
            ).fetchone()[0],
            "arubanetworks",
        )
        # ...and it healed the placeholder attribution while it was in there.
        self.assertEqual(
            conn.execute(
                "SELECT v.name FROM product p JOIN vendor v ON v.vendor_id = p.vendor_id "
                "WHERE p.product_id = 1"
            ).fetchone()[0],
            "arubanetworks",
        )

        # Second call must be a no-op, not a rebuild.
        apply_sqlite_migrations(conn)
        conn.commit()
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM product_cpe_vendor").fetchone()[0], 1
        )
        conn.close()


if __name__ == "__main__":
    unittest.main()
