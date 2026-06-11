"""Tests for the direct-SQL NVD bulk merger."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.cve import CVE
from vulnify.models.vendor import Vendor
from vulnify.providers.nvd import merge_nvd_cve_into_db


def _seed_cve(store: SqliteCveStore, cve_id: str) -> None:
    """Insert a minimal CVE row so the merger has something to update."""
    cve = CVE(
        cve_id=cve_id,
        title="t",
        cna="c",
        primary_vendor=Vendor(),
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
        modified=datetime(2024, 1, 1, tzinfo=timezone.utc),
        discovered=datetime.min.replace(tzinfo=timezone.utc),
    )
    store.upsert_cve(cve)


def _nvd_doc(cve_id: str) -> dict:
    """Realistic NVD 2.0 ``vulnerabilities[].cve`` shape for a single CVE."""
    return {
        "id": cve_id,
        "vulnStatus": "Analyzed",
        "sourceIdentifier": "nvd@nist.gov",
        "lastModified": "2026-04-01T12:00:00.000",
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9,
                }
            ]
        },
        "weaknesses": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [{"lang": "en", "value": "CWE-787"}],
            }
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                "matchCriteriaId": "abc-123",
                                "vulnerable": True,
                            }
                        ],
                    }
                ]
            }
        ],
        "references": [
            {
                "url": "https://example.com/advisory",
                "source": "vendor@example.com",
                "tags": ["Vendor Advisory", "Patch"],
            },
            {
                "url": "https://example.com/exploit",
                "source": "research@example.com",
                "tags": ["Exploit"],
            },
        ],
    }


class NvdBulkMergeTests(unittest.TestCase):
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

    def test_merge_populates_status_cvss_cwe_cpe_refs(self) -> None:
        cve_id = "CVE-2026-NVD1"
        with SqliteCveStore(self.db_path) as store:
            _seed_cve(store, cve_id)
            ok = merge_nvd_cve_into_db(store.connection, _nvd_doc(cve_id))
            store.connection.commit()
            cur = store.connection.cursor()
            cur.execute(
                "SELECT vuln_status, source_identifier, modified FROM cve WHERE cve_id = ?",
                (cve_id,),
            )
            row = cur.fetchone()
            cur.execute("SELECT COUNT(*) FROM cvss WHERE cve_id = ?", (cve_id,))
            cvss_n = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM cve_cwe WHERE cve_id = ?", (cve_id,))
            cwe_n = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM cpe_match WHERE cve_id = ?", (cve_id,))
            cpe_n = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM reference WHERE cve_id = ?", (cve_id,))
            ref_n = int(cur.fetchone()[0])
            cur.execute(
                "SELECT tag FROM reference_tag rt JOIN reference r ON r.id = rt.reference_id "
                "WHERE r.cve_id = ? ORDER BY tag",
                (cve_id,),
            )
            tags = [r["tag"] for r in cur.fetchall()]
        self.assertTrue(ok)
        assert row is not None
        self.assertEqual(row["vuln_status"], "Analyzed")
        self.assertEqual(row["source_identifier"], "nvd@nist.gov")
        self.assertTrue(row["modified"].startswith("2026-04-01"))
        self.assertEqual(cvss_n, 1)
        self.assertEqual(cwe_n, 1)
        self.assertEqual(cpe_n, 1)
        self.assertEqual(ref_n, 2)
        self.assertEqual(tags, ["Exploit", "Patch", "Vendor Advisory"])

    def test_merge_is_idempotent(self) -> None:
        cve_id = "CVE-2026-NVD2"
        with SqliteCveStore(self.db_path) as store:
            _seed_cve(store, cve_id)
            doc = _nvd_doc(cve_id)
            merge_nvd_cve_into_db(store.connection, doc)
            merge_nvd_cve_into_db(store.connection, doc)
            store.connection.commit()
            cur = store.connection.cursor()
            cur.execute("SELECT COUNT(*) FROM cvss WHERE cve_id = ?", (cve_id,))
            cvss_n = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM cve_cwe WHERE cve_id = ?", (cve_id,))
            cwe_n = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM cpe_match WHERE cve_id = ?", (cve_id,))
            cpe_n = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM reference WHERE cve_id = ?", (cve_id,))
            ref_n = int(cur.fetchone()[0])
        self.assertEqual(cvss_n, 1)
        self.assertEqual(cwe_n, 1)
        self.assertEqual(cpe_n, 1)
        self.assertEqual(ref_n, 2)

    def test_merge_skips_unknown_cve(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            ok = merge_nvd_cve_into_db(
                store.connection, _nvd_doc("CVE-2026-MISSING")
            )
            store.connection.commit()
        self.assertFalse(ok)

    def test_repeated_cpe_within_one_doc_collapses(self) -> None:
        cve_id = "CVE-2026-NVD4"
        with SqliteCveStore(self.db_path) as store:
            _seed_cve(store, cve_id)
            doc = _nvd_doc(cve_id)
            same = doc["configurations"][0]["nodes"][0]["cpeMatch"][0]
            # Same CPE pair listed under two configurations (NVD does this when
            # the criteria appears in multiple AND-clauses).
            doc["configurations"].append(
                {"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [same]}]}
            )
            doc["configurations"][0]["nodes"][0]["cpeMatch"].append(same)
            merge_nvd_cve_into_db(store.connection, doc)
            store.connection.commit()
            cur = store.connection.cursor()
            cur.execute("SELECT COUNT(*) FROM cpe_match WHERE cve_id = ?", (cve_id,))
            n = int(cur.fetchone()[0])
        self.assertEqual(n, 1)

    def test_merge_does_not_clobber_cisa_sourced_kev(self) -> None:
        cve_id = "CVE-2026-NVD3"
        with SqliteCveStore(self.db_path) as store:
            _seed_cve(store, cve_id)
            cur = store.connection.cursor()
            cur.execute(
                "UPDATE kev SET listed = 1, source = 'cisa' WHERE cve_id = ?",
                (cve_id,),
            )
            store.connection.commit()
            doc = _nvd_doc(cve_id)
            doc["cisaExploitAdd"] = "2026-01-15"
            doc["cisaActionDue"] = "2026-02-05"
            doc["cisaRequiredAction"] = "Apply patches"
            doc["cisaVulnerabilityName"] = "Some RCE"
            merge_nvd_cve_into_db(store.connection, doc)
            store.connection.commit()
            cur.execute("SELECT source, notes FROM kev WHERE cve_id = ?", (cve_id,))
            row = cur.fetchone()
        assert row is not None
        self.assertEqual(row["source"], "cisa")
        # CISA-owned row should not have been overwritten with NVD's notes.
        self.assertNotEqual(row["notes"], "Apply patches")


if __name__ == "__main__":
    unittest.main()
