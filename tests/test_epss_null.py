"""EPSS "not scored" is NULL, never 0.0.

FIRST's floor is above zero, so a stored 0.0 reads as "scored, negligible" —
the same null → false collapse the exploit tri-state forbids.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from vulnify.db.migrate import apply_sqlite_migrations
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.cve import CVE


class EpssNullTests(unittest.TestCase):
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

    def _epss(self, store: SqliteCveStore, cve_id: str):
        return store.connection.execute(
            "SELECT epss_score, epss_percentile FROM intel WHERE cve_id = ?", (cve_id,)
        ).fetchone()

    def test_an_ingested_cve_is_unscored_not_zero(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            store.upsert_cve(CVE(cve_id="CVE-2026-0001"))
            self.assertEqual(tuple(self._epss(store, "CVE-2026-0001")), (None, None))
            self.assertIsNone(store.get_cve("CVE-2026-0001").intel.epss_score)

    def test_a_reingest_degrades_a_score_to_null_not_zero(self) -> None:
        """Cascade + heal: the re-ingest wipes the score until EPSS re-runs.

        The wipe is expected; what matters is the direction — unknown, never a
        fabricated 0.0.
        """
        with SqliteCveStore(self.db_path) as store:
            store.upsert_cve(CVE(cve_id="CVE-2026-0002"))
            store.connection.execute(
                "UPDATE intel SET epss_score = 0.42, epss_percentile = 0.9 "
                "WHERE cve_id = 'CVE-2026-0002'")
            store.connection.commit()
            store.upsert_cve(CVE(cve_id="CVE-2026-0002"))
            self.assertEqual(tuple(self._epss(store, "CVE-2026-0002")), (None, None))

    def test_migration_nulls_the_old_default_and_keeps_real_scores(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            conn = store.connection
            for cid in ("CVE-2026-0003", "CVE-2026-0004"):
                store.upsert_cve(CVE(cve_id=cid))
            conn.execute("UPDATE intel SET epss_score = 0.0, epss_percentile = 0.0 "
                         "WHERE cve_id = 'CVE-2026-0003'")
            conn.execute("UPDATE intel SET epss_score = 0.0001, epss_percentile = 0.02 "
                         "WHERE cve_id = 'CVE-2026-0004'")
            apply_sqlite_migrations(conn)
            self.assertEqual(tuple(self._epss(store, "CVE-2026-0003")), (None, None))
            self.assertEqual(tuple(self._epss(store, "CVE-2026-0004")), (0.0001, 0.02))


if __name__ == "__main__":
    unittest.main()
