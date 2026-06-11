from __future__ import annotations

import os
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

from vulnify.constants import ExploitMaturity, ProductType, Severity, SourceTrust
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.affected import AffectedProduct
from vulnify.models.cvss import CVSS
from vulnify.models.cwe import CWE
from vulnify.models.cve import CVE
from vulnify.models.exploit import ExploitInfo
from vulnify.models.kev import KEVStatus
from vulnify.models.reference import Reference
from vulnify.models.threat_intel import ThreatIntel
from vulnify.models.vendor import Product, Vendor
from vulnify.models.version import VersionRange


class SqliteRoundTripTests(unittest.TestCase):
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

    def test_upsert_get_roundtrip(self) -> None:
        vendor = Vendor(name="VendorCo", website="https://vc.example", country="CA")
        primary = Vendor(name="PrimaryOrg", website="", country="")

        original = CVE(
            cve_id="CVE-2026-4242",
            title="Round-trip title",
            cna="vendorco",
            primary_vendor=primary,
            published=datetime(2026, 4, 1, 12, tzinfo=timezone.utc),
            modified=datetime(2026, 4, 2, tzinfo=timezone.utc),
            discovered=_dt_sentinel(),
            summary="One-line summary",
            technical_details="Longer technical text",
            cwes=[
                CWE(cwe_id="CWE-787", name="Out-of-bounds Write", description="desc"),
            ],
            cvss_scores=[
                CVSS(
                    version="3.1",
                    score=7.5,
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    severity=Severity.HIGH,
                    attack_vector="NETWORK",
                    confidentiality="NONE",
                ),
            ],
            affected_products=[
                AffectedProduct(
                    product=Product(
                        name="svc",
                        vendor=vendor,
                        product_type=ProductType.APPLICATION,
                        family="core",
                        component="api",
                    ),
                    versions=[
                        VersionRange(start_including="2.0", fixed_version="2.0.1"),
                    ],
                    affected=True,
                    notes="affected note",
                ),
            ],
            exploit=ExploitInfo(
                maturity=ExploitMaturity.FUNCTIONAL,
                public_poc=True,
                in_the_wild=False,
            ),
            kev=KEVStatus(listed=False, date_added=date.min, due_date=date(2026, 6, 1)),
            intel=ThreatIntel(
                epss_score=0.1,
                epss_percentile=0.25,
                known_actors=["grp1"],
                malware_families=["fam1"],
                campaigns=["cmp1"],
            ),
            references=[
                Reference(
                    url="https://nvd.nist.gov/",
                    source="NVD",
                    title="ref title",
                    tags=["official"],
                    trust=SourceTrust.NVD,
                ),
            ],
            tags=["urgent"],
            priority_score=3,
            confidence=0.85,
            extra={
                "dataVersion": "5.1",
                "dataType": "CVE_RECORD",
                "state": "PUBLISHED",
                "assignerOrgId": "org-uuid",
            },
        )

        with SqliteCveStore(self.db_path) as store:
            store.init_schema()
            store.upsert_cve(original)
        with SqliteCveStore(self.db_path) as store2:
            loaded = store2.get_cve("CVE-2026-4242")

        assert loaded is not None
        self.assertEqual(loaded.cve_id, original.cve_id)
        self.assertEqual(loaded.summary, original.summary)
        self.assertEqual(loaded.technical_details, original.technical_details)
        self.assertEqual(loaded.priority_score, original.priority_score)
        self.assertAlmostEqual(loaded.confidence, original.confidence)

        self.assertEqual(len(loaded.cvss_scores), 1)
        self.assertEqual(loaded.cvss_scores[0].score, 7.5)
        self.assertEqual(loaded.cvss_scores[0].severity, Severity.HIGH)

        self.assertEqual(len(loaded.affected_products), 1)
        self.assertEqual(loaded.affected_products[0].product.name, "svc")
        self.assertEqual(loaded.affected_products[0].product.vendor.name, "VendorCo")
        self.assertEqual(len(loaded.affected_products[0].versions), 1)
        self.assertEqual(loaded.affected_products[0].versions[0].start_including, "2.0")

        self.assertEqual(loaded.cwes[0].cwe_id, "CWE-787")

        self.assertEqual(loaded.exploit.maturity, ExploitMaturity.FUNCTIONAL)
        self.assertTrue(loaded.exploit.public_poc)
        # metasploit was never set on the source record — it must round-trip as
        # None ("not assessed"), not False ("assessed, no module").
        self.assertIsNone(loaded.exploit.metasploit)

        self.assertFalse(loaded.kev.listed)
        self.assertEqual(loaded.kev.due_date, date(2026, 6, 1))

        self.assertEqual(loaded.intel.known_actors, ["grp1"])
        self.assertEqual(loaded.intel.malware_families, ["fam1"])
        self.assertEqual(loaded.intel.campaigns, ["cmp1"])

        self.assertEqual(loaded.references[0].tags, ["official"])
        self.assertEqual(loaded.tags, ["urgent"])

        self.assertEqual(loaded.extra.get("assignerOrgId"), "org-uuid")
        self.assertEqual(loaded.extra.get("dataType"), "CVE_RECORD")


def _dt_sentinel() -> datetime:
    return datetime.min.replace(tzinfo=timezone.utc)
