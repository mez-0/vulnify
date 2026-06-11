"""Integration test for the dedup migration backfill on a pre-populated DB."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from vulnify.db.migrate import apply_sqlite_migrations


class MigrationBackfillTests(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        self.schema_path = repo_root / "vulnify" / "db" / "schema.sql"
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(self.schema_path)
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp.name)
        tmp.close()

    def tearDown(self) -> None:
        self.db_path.unlink(missing_ok=True)

    def _bootstrap(self) -> sqlite3.Connection:
        """Boot the schema without running migrations, to seed legacy duplicates."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(self.schema_path.read_text(encoding="utf-8"))
        # Drop the unique indexes we want to test the migration creates.
        conn.execute("DROP INDEX IF EXISTS affected_product_unique")
        conn.execute("DROP INDEX IF EXISTS product_normalized_unique")
        return conn

    def test_dedupes_legacy_data_and_creates_unique_indexes(self) -> None:
        conn = self._bootstrap()
        cur = conn.cursor()
        cur.executescript(
            """
            INSERT INTO cve (cve_id, title, summary, published, modified)
            VALUES ('CVE-2025-DUP', 't', 's', '2025-01-01', '2025-01-02');

            INSERT INTO vendor (vendor_id, name) VALUES (1, 'Acme'), (2, '');

            INSERT INTO product (product_id, name, vendor_id, component)
            VALUES (1, 'Linux Kernel', 1, ''),
                   (2, 'linux kernel', 1, ''),
                   (3, 'Foo',          1, '');

            INSERT INTO affected_product (cve_id, product_id, affected, notes)
            VALUES ('CVE-2025-DUP', 1, 1, ''),
                   ('CVE-2025-DUP', 1, 1, ''),
                   ('CVE-2025-DUP', 2, 1, ''),
                   ('CVE-2025-DUP', 3, 1, '');
            """
        )
        conn.commit()

        apply_sqlite_migrations(conn)
        conn.commit()

        cur.execute(
            "SELECT COUNT(*) FROM affected_product WHERE cve_id='CVE-2025-DUP'"
        )
        self.assertEqual(int(cur.fetchone()[0]), 2)  # 2 distinct products after merge

        cur.execute(
            "SELECT COUNT(*) FROM product WHERE lower(trim(name))='linux kernel'"
        )
        self.assertEqual(int(cur.fetchone()[0]), 1)

        cur.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='index' AND name='affected_product_unique'"
        )
        self.assertIsNotNone(cur.fetchone())
        cur.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='index' AND name='product_normalized_unique'"
        )
        self.assertIsNotNone(cur.fetchone())

        # Empty-name vendor with no edges should have been swept.
        cur.execute("SELECT COUNT(*) FROM vendor WHERE trim(COALESCE(name,''))=''")
        self.assertEqual(int(cur.fetchone()[0]), 0)

        conn.close()


    def test_exploit_signals_become_nullable_and_legacy_zeros_nulled(self) -> None:
        conn = self._bootstrap()
        cur = conn.cursor()
        # Drop the freshly-bootstrapped (already-nullable) exploit table and
        # recreate it with the legacy NOT NULL DEFAULT 0 declaration.
        cur.executescript(
            """
            DROP TABLE IF EXISTS exploit;
            CREATE TABLE exploit (
                cve_id TEXT PRIMARY KEY,
                maturity TEXT,
                public_poc INTEGER NOT NULL DEFAULT 0,
                metasploit INTEGER NOT NULL DEFAULT 0,
                ransomware_usage INTEGER NOT NULL DEFAULT 0,
                in_the_wild INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
            );
            INSERT INTO cve (cve_id, title, summary, published, modified)
            VALUES ('CVE-2025-EXP', 't', 's', '2025-01-01', '2025-01-02');
            INSERT INTO exploit
                (cve_id, maturity, public_poc, metasploit, ransomware_usage, in_the_wild, notes)
            VALUES ('CVE-2025-EXP', 'NONE', 0, 0, 0, 1, '');
            """
        )
        conn.commit()

        # Sanity: legacy column is NOT NULL before migration.
        cur.execute("PRAGMA table_info(exploit)")
        before = {row[1]: row[3] for row in cur.fetchall()}
        self.assertEqual(before["public_poc"], 1)

        apply_sqlite_migrations(conn)
        conn.commit()

        cur.execute("PRAGMA table_info(exploit)")
        after = {row[1]: row[3] for row in cur.fetchall()}
        self.assertEqual(after["public_poc"], 0)  # now nullable
        self.assertEqual(after["metasploit"], 0)

        cur.execute(
            "SELECT public_poc, metasploit, in_the_wild "
            "FROM exploit WHERE cve_id='CVE-2025-EXP'"
        )
        row = cur.fetchone()
        self.assertIsNone(row["public_poc"])  # legacy 0 recovered to NULL
        self.assertIsNone(row["metasploit"])
        self.assertEqual(int(row["in_the_wild"]), 1)  # real signal preserved

        # Idempotent: a second pass must not error or re-touch the table.
        apply_sqlite_migrations(conn)
        conn.commit()
        conn.close()

    def test_exploit_artefact_table_created_and_cascades(self) -> None:
        conn = self._bootstrap()
        cur = conn.cursor()
        # Simulate an older DB that bootstrapped before exploit_artefact existed:
        # drop the schema-created table + index so the migration must recreate.
        cur.executescript(
            """
            DROP INDEX IF EXISTS exploit_artefact_unique;
            DROP TABLE IF EXISTS exploit_artefact;
            """
        )
        conn.commit()
        self.assertFalse(
            self._table_present(cur, "exploit_artefact"),
            "precondition: table dropped before migration",
        )

        apply_sqlite_migrations(conn)
        conn.commit()

        # Table exists with the expected columns.
        cur.execute("PRAGMA table_info(exploit_artefact)")
        cols = {row[1]: row for row in cur.fetchall()}
        self.assertEqual(
            set(cols),
            {
                "id",
                "cve_id",
                "source",
                "stable_id",
                "url",
                "artefact_type",
                "platform",
                "published_date",
                "confidence",
            },
        )
        # source/confidence are NOT NULL; the rest are nullable.
        self.assertEqual(cols["source"][3], 1)
        self.assertEqual(cols["confidence"][3], 1)
        self.assertEqual(cols["stable_id"][3], 0)

        # Unique index on (cve_id, source, stable_id) exists.
        self.assertTrue(self._index_present(cur, "exploit_artefact_unique"))

        # Cascade: an artefact row dies with its CVE.
        cur.executescript(
            """
            INSERT INTO cve (cve_id, title, summary, published, modified)
            VALUES ('CVE-2025-ART', 't', 's', '2025-01-01', '2025-01-02');
            INSERT INTO exploit_artefact
                (cve_id, source, stable_id, url, confidence)
            VALUES ('CVE-2025-ART', 'nuclei', 'CVE-2025-ART.yaml',
                    'https://example/template', 'exact');
            """
        )
        conn.commit()
        cur.execute(
            "SELECT COUNT(*) FROM exploit_artefact WHERE cve_id='CVE-2025-ART'"
        )
        self.assertEqual(int(cur.fetchone()[0]), 1)

        cur.execute("DELETE FROM cve WHERE cve_id='CVE-2025-ART'")
        conn.commit()
        cur.execute(
            "SELECT COUNT(*) FROM exploit_artefact WHERE cve_id='CVE-2025-ART'"
        )
        self.assertEqual(int(cur.fetchone()[0]), 0)

        # Idempotent: a second pass is a no-op, not an error.
        apply_sqlite_migrations(conn)
        conn.commit()
        conn.close()

    @staticmethod
    def _table_present(cur: sqlite3.Cursor, name: str) -> bool:
        cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (name,),
        )
        return cur.fetchone() is not None

    @staticmethod
    def _index_present(cur: sqlite3.Cursor, name: str) -> bool:
        cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name=? LIMIT 1",
            (name,),
        )
        return cur.fetchone() is not None


if __name__ == "__main__":
    unittest.main()
