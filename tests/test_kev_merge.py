"""KEV merges in place and never cascades away out-of-registry enrichment.

The old path (``get_cve`` → apply → ``upsert_cve``) deleted and rebuilt the
CVE; ``exploit_artefact`` rows and ``osv_checked`` markers are written outside
the registry, so a catalog refresh without an exploit re-parse stripped them —
1,947 artefacts in one run, all on KEV-listed CVEs.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.cve import CVE
from vulnify.providers.cisa_kev import ingest_cisa_kev_catalog

ENTRY = {
    "cveID": "CVE-2026-0100",
    "vendorProject": "Citrix",
    "product": "NetScaler",
    "vulnerabilityName": "Citrix NetScaler Memory Buffer Vulnerability",
    "dateAdded": "2026-09-27",
    "shortDescription": "A memory buffer vulnerability.",
    "requiredAction": "Apply mitigations.",
    "dueDate": "2026-09-30",
    "knownRansomwareCampaignUse": "Known",
    "notes": "https://example.test/advisory",
    "cwes": ["CWE-119"],
}


class KevMergeTests(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(
            repo_root / "vulnify" / "db" / "schema.sql"
        )
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "t.db"
        self.kev_path = Path(self.tmp.name) / "kev.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _ingest(self, store: SqliteCveStore, *entries: dict) -> int:
        self.kev_path.write_text(json.dumps(
            {"catalogVersion": "2026.09.30", "vulnerabilities": list(entries)}))
        return asyncio.run(
            ingest_cisa_kev_catalog(store, catalog_path=self.kev_path, force=True))

    def _seed(self, store: SqliteCveStore) -> None:
        store.upsert_cve(CVE(cve_id="CVE-2026-0100", title="cvelist title"))
        conn = store.connection
        conn.execute(
            "INSERT INTO exploit_artefact (cve_id, source, stable_id, confidence) "
            "VALUES ('CVE-2026-0100', 'exploitdb', '12345', 'high')")
        conn.execute(
            "INSERT INTO intel_string_list (cve_id, kind, value) "
            "VALUES ('CVE-2026-0100', 'osv_checked', '1')")
        conn.commit()

    def test_out_of_registry_enrichment_survives(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            self._seed(store)
            self._ingest(store, ENTRY)
            conn = store.connection
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM exploit_artefact").fetchone()[0], 1)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM intel_string_list WHERE kind = 'osv_checked'"
            ).fetchone()[0], 1)

    def test_kev_fields_are_merged(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            self._seed(store)
            self._ingest(store, ENTRY)
            got = store.get_cve("CVE-2026-0100")
        self.assertTrue(got.kev.listed)
        self.assertEqual(got.kev.source, "cisa")
        self.assertEqual(got.title, ENTRY["vulnerabilityName"])
        self.assertTrue(got.exploit.in_the_wild)
        self.assertTrue(got.exploit.ransomware_usage)
        self.assertIn("CWE-119", {c.cwe_id for c in got.cwes})
        self.assertIn("https://example.test/advisory", {r.url for r in got.references})
        self.assertEqual(got.primary_vendor.name, "Citrix")

    def test_a_real_primary_vendor_is_not_overwritten(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            cve = CVE(cve_id="CVE-2026-0100")
            cve.primary_vendor.name = "Cloud Software Group"
            store.upsert_cve(cve)
            self._ingest(store, ENTRY)
            self.assertEqual(
                store.get_cve("CVE-2026-0100").primary_vendor.name,
                "Cloud Software Group")

    def test_a_cve_missing_from_cvelist_gets_a_stub(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            self.assertEqual(self._ingest(store, ENTRY), 1)
            self.assertTrue(store.get_cve("CVE-2026-0100").kev.listed)

    def test_rerunning_is_idempotent(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            self._seed(store)
            self._ingest(store, ENTRY)
            self._ingest(store, ENTRY)
            conn = store.connection
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM reference WHERE cve_id = 'CVE-2026-0100'"
            ).fetchone()[0], 1)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM cve_vendor WHERE role = 'primary'"
            ).fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
