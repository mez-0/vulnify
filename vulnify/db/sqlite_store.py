from __future__ import annotations

import sqlite3
from pathlib import Path

from vulnify.constants import ExploitMaturity, ProductType, Severity, SourceTrust
from vulnify.db.cve_upsert import (
    CveUpsertContext,
    CveUpsertPolicy,
    CveUpsertRegistry,
    default_cve_upsert_registry,
)
from vulnify.db.sql_conversion import (
    sql_to_bool,
    sql_to_bool_nullable,
    sql_to_date,
    sql_to_datetime,
)
from vulnify.models.affected import AffectedProduct
from vulnify.models.cpe import CpeMatch
from vulnify.models.cvss import CVSS
from vulnify.models.cwe import CWE
from vulnify.models.cve import CVE
from vulnify.models.exploit import ExploitInfo
from vulnify.models.kev import KEVStatus
from vulnify.models.reference import Reference
from vulnify.models.threat_intel import ThreatIntel
from vulnify.models.vendor import Product, Vendor
from vulnify.models.version import VersionRange
from vulnify.db.migrate import apply_sqlite_migrations
from vulnify.settings import get_schema_sql_path


def _parse_severity(value: str | None) -> Severity:
    """
    Parse a severity.

    :param value: The value to parse.
    :type value: str | None
    :return: The severity, or UNKNOWN when the value is invalid.
    :rtype: Severity
    """
    if not value:
        return Severity.UNKNOWN
    try:
        return Severity(value)
    except ValueError:
        return Severity.UNKNOWN


def _parse_source_trust(value: str | None) -> SourceTrust:
    """
    Parse a source trust.

    :param value: The value to parse.
    :type value: str | None
    :return: The source trust, or COMMUNITY when the value is invalid.
    :rtype: SourceTrust
    """
    if not value:
        return SourceTrust.COMMUNITY
    try:
        return SourceTrust(value)
    except ValueError:
        return SourceTrust.COMMUNITY


def _parse_exploit_maturity(value: str | None) -> ExploitMaturity:
    """
    Parse an exploit maturity.

    :param value: The value to parse.
    :type value: str | None
    :return: The exploit maturity, or NONE when the value is invalid.
    :rtype: ExploitMaturity
    """
    if not value:
        return ExploitMaturity.NONE
    try:
        return ExploitMaturity(value)
    except ValueError:
        return ExploitMaturity.NONE


def _parse_product_type(value: str | None) -> ProductType:
    """
    Parse a product type.

    :param value: The value to parse.
    :type value: str | None
    :return: The product type, or UNKNOWN when the value is invalid.
    :rtype: ProductType
    """
    if not value:
        return ProductType.UNKNOWN
    try:
        return ProductType(value)
    except ValueError:
        return ProductType.UNKNOWN


def _row_text(row: sqlite3.Row, key: str) -> str:
    if key not in row.keys():
        return ""
    val = row[key]
    return "" if val is None else str(val)


def _load_vendor(cur: sqlite3.Cursor, vendor_id: int) -> Vendor:
    cur.execute(
        "SELECT name, website, country FROM vendor WHERE vendor_id = ?",
        (vendor_id,),
    )
    row = cur.fetchone()
    if not row:
        return Vendor()
    return Vendor(
        name=row["name"] or "",
        website=row["website"] or "",
        country=row["country"] or "",
    )


class SqliteCveStore:
    """SQLite-backed persistence for :class:`~vulnify.models.cve.CVE` records."""

    def __init__(
        self,
        path: str | Path,
        *,
        upsert_registry: CveUpsertRegistry | None = None,
    ) -> None:
        self._path = Path(path)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._upsert_registry = upsert_registry or default_cve_upsert_registry()

        self.init_schema()

    @property
    def path(self) -> Path:
        """
        Get the path to the SQLite database.

        :return: The path to the SQLite database.
        :rtype: Path
        """
        return self._path

    @property
    def connection(self) -> sqlite3.Connection:
        """
        Get the SQLite connection.

        :return: The SQLite connection.
        :rtype: sqlite3.Connection
        """
        return self._conn

    @property
    def upsert_registry(self) -> CveUpsertRegistry:
        """
        Get the CVE upsert registry.

        :return: The CVE upsert registry.
        :rtype: CveUpsertRegistry
        """
        return self._upsert_registry

    def init_schema(self) -> None:
        """
        Initialize the SQLite schema.

        :return: None
        :rtype: None
        """
        ddl = get_schema_sql_path().read_text(encoding="utf-8")
        self._conn.executescript(ddl)
        apply_sqlite_migrations(self._conn)
        self._conn.commit()

    def close(self) -> None:
        """
        Close the SQLite connection.

        :return: None
        :rtype: None
        """
        self._conn.close()

    def __enter__(self) -> SqliteCveStore:
        """
        Enter the context manager.

        :return: The SQLite CVE store.
        :rtype: SqliteCveStore
        """
        return self

    def __exit__(self, *_exc: object) -> None:
        """
        Exit the context manager.

        :param _exc: The exception.
        :type _exc: object
        :return: None
        :rtype: None
        """
        self.close()

    def ensure_vendor(self, cur: sqlite3.Cursor, vendor: Vendor) -> int:
        """
        Ensure a vendor.

        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param vendor: The vendor.
        :type vendor: Vendor
        :return: The vendor ID.
        :rtype: int
        """
        name = (vendor.name or "").strip()
        cur.execute(
            "SELECT vendor_id FROM vendor WHERE lower(trim(name)) = lower(trim(?))",
            (name,),
        )
        row = cur.fetchone()
        if row:
            return int(row["vendor_id"])
        cur.execute(
            "INSERT INTO vendor (name, website, country) VALUES (?, ?, ?)",
            (name, vendor.website or "", vendor.country or ""),
        )
        return int(cur.lastrowid)

    def ensure_product(
        self, cur: sqlite3.Cursor, product: Product, vendor_id: int
    ) -> int:
        """
        Ensure a product.

        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param product: The product.
        :type product: Product
        :param vendor_id: The vendor ID.
        :type vendor_id: int
        :return: The product ID.
        :rtype: int
        """
        pname = product.name or ""
        component = product.component or ""
        cur.execute(
            """
            SELECT product_id FROM product
            WHERE vendor_id = ?
              AND lower(trim(name)) = lower(trim(?))
              AND lower(trim(COALESCE(component, ''))) = lower(trim(?))
            """,
            (vendor_id, pname, component),
        )
        row = cur.fetchone()
        if row:
            return int(row["product_id"])
        cur.execute(
            """
            INSERT INTO product (name, vendor_id, product_type, family, component)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                pname,
                vendor_id,
                product.product_type.value,
                product.family or "",
                component,
            ),
        )
        return int(cur.lastrowid)

    def ensure_tag_id(self, cur: sqlite3.Cursor, name: str) -> int:
        """
        Ensure a tag ID.

        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param name: The tag name.
        :type name: str
        :return: The tag ID.
        :rtype: int
        """
        cur.execute("SELECT id FROM tag WHERE name = ?", (name,))
        row = cur.fetchone()
        if row:
            return int(row["id"])
        cur.execute("INSERT INTO tag (name) VALUES (?)", (name,))
        return int(cur.lastrowid)

    def upsert_cve(
        self,
        cve: CVE,
        *,
        policy: CveUpsertPolicy | None = None,
        registry: CveUpsertRegistry | None = None,
    ) -> None:
        """
        Upsert a CVE.

        :param cve: The CVE.
        :type cve: CVE
        :param policy: The CVE upsert policy.
        :type policy: CveUpsertPolicy | None
        :param registry: The CVE upsert registry.
        :type registry: CveUpsertRegistry | None
        :return: None
        :rtype: None
        """
        if not cve.cve_id.strip():
            raise ValueError("CVE requires a non-empty cve_id")

        ctx = CveUpsertContext.build(cve, policy)
        reg = registry or self._upsert_registry
        conn = self._conn
        cur = conn.cursor()
        try:
            cur.execute("BEGIN")
            reg.run(self, cur, ctx)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def get_cve(self, cve_id: str) -> CVE | None:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,))
        crow = cur.fetchone()
        if not crow:
            return None

        extra: dict[str, str] = {}
        if crow["data_version"]:
            extra["dataVersion"] = crow["data_version"]
        if crow["data_type"]:
            extra["dataType"] = crow["data_type"]
        if crow["state"]:
            extra["state"] = crow["state"]
        if crow["assigner_org_id"]:
            extra["assignerOrgId"] = crow["assigner_org_id"]

        primary_vendor = Vendor()
        cur.execute(
            """
            SELECT vendor_id FROM cve_vendor
            WHERE cve_id = ? AND role = 'primary'
            LIMIT 1
            """,
            (cve_id,),
        )
        pr = cur.fetchone()
        if pr:
            primary_vendor = _load_vendor(cur, int(pr["vendor_id"]))

        affected_products: list[AffectedProduct] = []
        cur.execute(
            """
            SELECT ap.id AS ap_id, ap.affected, ap.notes, ap.product_id
            FROM affected_product ap
            WHERE ap.cve_id = ?
            ORDER BY ap.id
            """,
            (cve_id,),
        )
        for ap_row in cur.fetchall():
            cur.execute(
                """
                SELECT p.name, p.vendor_id, p.product_type, p.family, p.component
                FROM product p WHERE p.product_id = ?
                """,
                (ap_row["product_id"],),
            )
            prow = cur.fetchone()
            if not prow:
                continue
            vendor = _load_vendor(cur, int(prow["vendor_id"]))
            product = Product(
                name=prow["name"] or "",
                vendor=vendor,
                product_type=_parse_product_type(prow["product_type"]),
                family=prow["family"] or "",
                component=prow["component"] or "",
            )
            cur.execute(
                """
                SELECT start_including, start_excluding, end_including, end_excluding,
                       fixed_version, raw_text
                FROM version_range
                WHERE affected_product_id = ?
                ORDER BY id
                """,
                (ap_row["ap_id"],),
            )
            versions = [
                VersionRange(
                    start_including=r["start_including"] or "",
                    start_excluding=r["start_excluding"] or "",
                    end_including=r["end_including"] or "",
                    end_excluding=r["end_excluding"] or "",
                    fixed_version=r["fixed_version"] or "",
                    raw_text=r["raw_text"] or "",
                )
                for r in cur.fetchall()
            ]
            affected_products.append(
                AffectedProduct(
                    product=product,
                    versions=versions,
                    affected=sql_to_bool(ap_row["affected"]),
                    notes=ap_row["notes"] or "",
                )
            )

        cwes: list[CWE] = []
        cur.execute(
            """
            SELECT c.cwe_id, c.name, c.description
            FROM cwe c
            JOIN cve_cwe cc ON cc.cwe_id = c.cwe_id
            WHERE cc.cve_id = ?
            ORDER BY c.cwe_id
            """,
            (cve_id,),
        )
        for r in cur.fetchall():
            cwes.append(
                CWE(
                    cwe_id=r["cwe_id"] or "",
                    name=r["name"] or "",
                    description=r["description"] or "",
                )
            )

        cvss_scores: list[CVSS] = []
        cur.execute(
            """
            SELECT version, score, vector, severity,
                   attack_vector, attack_complexity, privileges_required,
                   user_interaction, scope,
                   confidentiality, integrity, availability,
                   metric_source, metric_type, exploitability_score, impact_score
            FROM cvss WHERE cve_id = ? ORDER BY id
            """,
            (cve_id,),
        )
        for r in cur.fetchall():
            cvss_scores.append(
                CVSS(
                    version=r["version"] or "",
                    score=float(r["score"] or 0.0),
                    vector=r["vector"] or "",
                    severity=_parse_severity(r["severity"]),
                    attack_vector=r["attack_vector"] or "",
                    attack_complexity=r["attack_complexity"] or "",
                    privileges_required=r["privileges_required"] or "",
                    user_interaction=r["user_interaction"] or "",
                    scope=r["scope"] or "",
                    confidentiality=r["confidentiality"] or "",
                    integrity=r["integrity"] or "",
                    availability=r["availability"] or "",
                    metric_source=_row_text(r, "metric_source"),
                    metric_type=_row_text(r, "metric_type"),
                    exploitability_score=float(r["exploitability_score"] or 0.0),
                    impact_score=float(r["impact_score"] or 0.0),
                )
            )

        exploit_row = cur.execute(
            "SELECT * FROM exploit WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if exploit_row:
            exploit = ExploitInfo(
                maturity=_parse_exploit_maturity(exploit_row["maturity"]),
                public_poc=sql_to_bool_nullable(exploit_row["public_poc"]),
                metasploit=sql_to_bool_nullable(exploit_row["metasploit"]),
                ransomware_usage=sql_to_bool(exploit_row["ransomware_usage"]),
                in_the_wild=sql_to_bool(exploit_row["in_the_wild"]),
                notes=exploit_row["notes"] or "",
            )
        else:
            exploit = ExploitInfo()

        kev_row = cur.execute(
            "SELECT * FROM kev WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if kev_row:
            kev = KEVStatus(
                listed=sql_to_bool(kev_row["listed"]),
                date_added=sql_to_date(kev_row["date_added"]),
                due_date=sql_to_date(kev_row["due_date"]),
                notes=kev_row["notes"] or "",
                vulnerability_name=_row_text(kev_row, "vulnerability_name"),
                required_action=_row_text(kev_row, "required_action"),
                vendor_project=_row_text(kev_row, "vendor_project"),
                product_label=_row_text(kev_row, "product_label"),
                short_description=_row_text(kev_row, "short_description"),
                source=_row_text(kev_row, "source"),
            )
        else:
            kev = KEVStatus()

        intel_row = cur.execute(
            "SELECT * FROM intel WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        known_actors: list[str] = []
        malware_families: list[str] = []
        campaigns: list[str] = []
        osv_packages: list[str] = []
        cur.execute(
            "SELECT kind, value FROM intel_string_list WHERE cve_id = ? ORDER BY id",
            (cve_id,),
        )
        for ir in cur.fetchall():
            k, v = ir["kind"], ir["value"]
            if k == "actor":
                known_actors.append(v)
            elif k == "malware":
                malware_families.append(v)
            elif k == "campaign":
                campaigns.append(v)
            elif k == "osv_package":
                osv_packages.append(v)

        if intel_row:
            intel = ThreatIntel(
                epss_score=intel_row["epss_score"],
                epss_percentile=intel_row["epss_percentile"],
                known_actors=known_actors,
                malware_families=malware_families,
                campaigns=campaigns,
                osv_packages=osv_packages,
            )
        else:
            intel = ThreatIntel(
                known_actors=known_actors,
                malware_families=malware_families,
                campaigns=campaigns,
                osv_packages=osv_packages,
            )

        cpe_matches: list[CpeMatch] = []
        cur.execute(
            """
            SELECT criteria, match_criteria_id, vulnerable
            FROM cpe_match WHERE cve_id = ? ORDER BY id
            """,
            (cve_id,),
        )
        for r in cur.fetchall():
            cpe_matches.append(
                CpeMatch(
                    criteria=r["criteria"] or "",
                    match_criteria_id=r["match_criteria_id"] or "",
                    vulnerable=sql_to_bool(r["vulnerable"]),
                )
            )

        references: list[Reference] = []
        cur.execute(
            "SELECT id, url, source, title, trust FROM reference WHERE cve_id = ? ORDER BY id",
            (cve_id,),
        )
        for r in cur.fetchall():
            cur.execute(
                "SELECT tag FROM reference_tag WHERE reference_id = ? ORDER BY tag",
                (r["id"],),
            )
            ref_tags = [row["tag"] for row in cur.fetchall()]
            references.append(
                Reference(
                    url=r["url"] or "",
                    source=r["source"] or "",
                    title=r["title"] or "",
                    tags=ref_tags,
                    trust=_parse_source_trust(r["trust"]),
                )
            )

        cur.execute(
            """
            SELECT t.name FROM tag t
            JOIN cve_tag ct ON ct.tag_id = t.id
            WHERE ct.cve_id = ?
            ORDER BY t.name
            """,
            (cve_id,),
        )
        tags = [row["name"] for row in cur.fetchall()]

        return CVE(
            cve_id=crow["cve_id"] or "",
            title=crow["title"] or "",
            cna=crow["cna"] or "",
            primary_vendor=primary_vendor,
            published=sql_to_datetime(crow["published"]),
            modified=sql_to_datetime(crow["modified"]),
            discovered=sql_to_datetime(crow["discovered"]),
            summary=crow["summary"] or "",
            technical_details=crow["technical_details"] or "",
            vuln_status=_row_text(crow, "vuln_status"),
            source_identifier=_row_text(crow, "source_identifier"),
            cwes=cwes,
            cvss_scores=cvss_scores,
            affected_products=affected_products,
            cpe_matches=cpe_matches,
            exploit=exploit,
            kev=kev,
            intel=intel,
            references=references,
            tags=tags,
            priority_score=int(crow["priority_score"] or 0),
            confidence=float(
                crow["confidence"] if crow["confidence"] is not None else 1.0
            ),
            extra=extra,
        )


__all__ = ["SqliteCveStore"]
