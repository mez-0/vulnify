import json
import re
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

from loguru import logger
from tqdm import tqdm

from vulnify.constants import SourceTrust
from vulnify.cvss_severity import severity_from_cvss_base
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.settings import get_sqlite_path_from_env
from vulnify.http import download_zip
from vulnify.models.affected import AffectedProduct
from vulnify.models.cve import CVE
from vulnify.models.cwe import CWE
from vulnify.models.cvss import CVSS
from vulnify.models.reference import Reference
from vulnify.models.vendor import Product, Vendor
from vulnify.models.version import VersionRange

ZIP_URL = "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-09-30_1200Z/2026-09-30_all_CVEs_at_midnight.zip.zip"

LOCAL_ZIP_PATH = Path("/tmp/cveproject.zip")
UNZIPPED_PATH = Path("/tmp/cveproject")
UNZIPPED_PATH.mkdir(parents=True, exist_ok=True)

CVE_DIRECTORY = Path("/tmp/cveproject/cves")


async def process_cveproject(db_path: Path | None = None) -> bool:
    """
    Process the CVEProject.

    When ``db_path`` is set or the environment variable ``VULNIFY_SQLITE_PATH``
    is a non-empty path, CVE records are written to that SQLite database;
    otherwise each parsed CVE is printed to stdout.

    :param db_path: Optional SQLite file path (overrides ``VULNIFY_SQLITE_PATH``).
    :type db_path: Path | None
    :return: True if the CVEProject was processed successfully, False otherwise.
    :rtype: bool
    """

    sqlite_path = (
        db_path.resolve() if db_path is not None else get_sqlite_path_from_env()
    )

    if not sqlite_path:
        logger.warning("No SQLite database path provided")
        return False

    if not CVE_DIRECTORY.exists():
        if not await _download_and_unpack_cve_zip():
            return False

    store = SqliteCveStore(sqlite_path)

    logger.info(f"Writing CVEs to SQLite at {sqlite_path}")

    logger.info(f"Processing CVEProject from {CVE_DIRECTORY}")

    years = _get_years()

    try:
        for year in years:
            _process_year(year, store)
    finally:
        store.close()

    return True


def _process_year(year: int, store: SqliteCveStore) -> bool:
    """
    Process a year of the CVEProject.

    :param year: The year to process.
    :type year: int
    :param store: SQLite store for writes.
    :type store: SqliteCveStore
    :return: True if the year was processed successfully, False otherwise.
    :rtype: bool
    """
    year_directory = CVE_DIRECTORY / str(year)

    json_paths = [
        p for subdir in sorted(year_directory.iterdir()) for p in subdir.glob("*.json")
    ]

    for j in tqdm(json_paths, desc=str(year), unit="file"):
        cve = _process_json(j)
        if not cve:
            continue
        store.upsert_cve(cve)

    return True


def _process_json(json_path: Path) -> CVE | None:
    """
    Process a JSON file.

    :param json_path: The path to the JSON file.
    :type json_path: Path
    :return: A parsed CVE instance, or None when the record is invalid.
    :rtype: CVE | None
    """
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            record = json.load(f)
        return _cve_from_cve_project_record(record)
    except Exception as e:
        logger.error(f"Failed to read {json_path}: {e}")
        return None


def _cve_from_cve_project_record(record: dict) -> CVE | None:
    """
    Convert a CVEProject record to a CVE instance.

    :param record: The CVEProject record.
    :type record: dict
    :return: A parsed CVE instance, or None when the record is invalid.
    :rtype: CVE | None
    """

    metadata = record.get("cveMetadata", {})

    cve_id = metadata.get("cveId", "").strip()

    if not cve_id:
        return None

    containers = record.get("containers", {})

    cna = containers.get("cna", {})

    adp = containers.get("adp", [])

    adp_entries = adp if isinstance(adp, list) else []

    all_containers = [cna, *[entry for entry in adp_entries if isinstance(entry, dict)]]

    published = _parse_datetime(metadata.get("datePublished")) or datetime.min.replace(
        tzinfo=timezone.utc
    )

    modified = _parse_datetime(metadata.get("dateUpdated")) or datetime.min.replace(
        tzinfo=timezone.utc
    )

    discovered = _parse_datetime(cna.get("datePublic")) or datetime.min.replace(
        tzinfo=timezone.utc
    )

    summary = _first_en_description(cna.get("descriptions", []))

    title = str(cna.get("title", "")).strip()

    cve = CVE(
        cve_id=cve_id,
        cna=str(
            metadata.get("assignerShortName")
            or cna.get("providerMetadata", {}).get("shortName")
            or ""
        ),
        title=title,
        summary=summary,
        published=published,
        modified=modified,
        discovered=discovered,
        primary_vendor=_extract_primary_vendor(cna.get("affected", [])),
        affected_products=_extract_affected_products(cna.get("affected", [])),
        references=_extract_references(all_containers),
        cwes=_extract_cwes(cna.get("problemTypes", [])),
        cvss_scores=_extract_cvss_scores(all_containers),
        tags=_extract_tags(all_containers),
        extra={
            "dataVersion": str(record.get("dataVersion", "")),
            "dataType": str(record.get("dataType", "")),
            "state": str(metadata.get("state", "")),
            "assignerOrgId": str(metadata.get("assignerOrgId", "")),
        },
    )
    return cve


def _parse_datetime(value: str | None) -> datetime | None:
    """
    Parse a datetime string.

    :param value: The datetime string.
    :type value: str | None
    :return: A parsed datetime instance, or None when the string is invalid.
    :rtype: datetime | None
    """

    if not value:
        return None

    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)

    except ValueError:
        return None


def _first_en_description(descriptions: list[dict]) -> str:
    """
    Get the first English description.

    :param descriptions: The list of descriptions.
    :type descriptions: list[dict]
    :return: The first English description, or an empty string if no English description is found.
    :rtype: str
    """

    for desc in descriptions:
        if str(desc.get("lang", "")).lower() == "en":
            return str(desc.get("value", "")).strip()

    if descriptions:
        return str(descriptions[0].get("value", "")).strip()

    return ""


def _truthy_vendor(vendor_name: str) -> bool:
    """
    Check if a vendor name is truthy.

    :param vendor_name: The vendor name.
    :type vendor_name: str
    :return: True if the vendor name is truthy, False otherwise.
    :rtype: bool
    """

    return vendor_name.strip().lower() not in {"", "n/a", "na", "unknown", "none"}


def _extract_primary_vendor(affected_entries: list[dict]) -> Vendor:
    """
    Extract the primary vendor from the affected entries.

    :param affected_entries: The list of affected entries.
    :type affected_entries: list[dict]
    :return: The primary vendor, or an empty Vendor instance if no primary vendor is found.
    :rtype: Vendor
    """

    for affected in affected_entries:
        vendor_name = str(affected.get("vendor", "")).strip()
        if _truthy_vendor(vendor_name):
            return Vendor(name=vendor_name)
    return Vendor()


def _extract_affected_products(affected_entries: list[dict]) -> list[AffectedProduct]:
    """
    Extract the affected products from the affected entries.

    :param affected_entries: The list of affected entries.
    :type affected_entries: list[dict]
    :return: The list of affected products.
    :rtype: list[AffectedProduct]
    """
    products: list[AffectedProduct] = []
    for affected in affected_entries:
        vendor_name = str(affected.get("vendor", "")).strip()
        product_name = str(affected.get("product", "")).strip()
        if not product_name:
            continue
        vendor = Vendor(name=vendor_name) if _truthy_vendor(vendor_name) else Vendor()
        product = Product(name=product_name, vendor=vendor)
        versions = _extract_versions(affected.get("versions", []))
        products.append(AffectedProduct(product=product, versions=versions))
    return products


def _extract_versions(version_entries: list[dict]) -> list[VersionRange]:
    """
    Extract the versions from the version entries.

    :param version_entries: The list of version entries.
    :type version_entries: list[dict]
    :return: The list of versions.
    :rtype: list[VersionRange]
    """
    ranges: list[VersionRange] = []
    for entry in version_entries:
        status = str(entry.get("status", "")).lower()
        version = str(entry.get("version", "")).strip()
        version_range = VersionRange(
            start_including=(
                str(entry.get("version", "")).strip() if status == "affected" else ""
            ),
            end_excluding=str(entry.get("lessThan", "")).strip(),
            end_including=str(entry.get("lessThanOrEqual", "")).strip(),
            fixed_version=(
                str(entry.get("changes", [{}])[-1].get("at", "")).strip()
                if status == "unaffected" and entry.get("changes")
                else ""
            ),
            raw_text=version,
        )
        ranges.append(version_range)
    return ranges


def _extract_references(container_entries: list[dict]) -> list[Reference]:
    """
    Extract the references from the container entries.

    :param container_entries: The list of container entries.
    :type container_entries: list[dict]
    :return: The list of references.
    :rtype: list[Reference]
    """
    references: list[Reference] = []
    seen_urls: set[str] = set()
    for container in container_entries:
        for ref in container.get("references", []):
            url = str(ref.get("url", "")).strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            tags = [str(tag) for tag in ref.get("tags", []) if isinstance(tag, str)]
            source = "cna"
            for tag in tags:
                if tag.startswith("x_refsource_"):
                    source = tag.replace("x_refsource_", "")
                    break
            trust = (
                SourceTrust.VENDOR
                if any(tag == "vendor-advisory" for tag in tags)
                else SourceTrust.COMMUNITY
            )
            references.append(
                Reference(
                    url=url,
                    source=source,
                    title=str(ref.get("name", "")).strip(),
                    tags=tags,
                    trust=trust,
                )
            )
    return references


def _extract_tags(container_entries: list[dict]) -> list[str]:
    """
    Extract the tags from the container entries.

    :param container_entries: The list of container entries.
    :type container_entries: list[dict]
    :return: The list of tags.
    :rtype: list[str]
    """
    tags: set[str] = set()
    for container in container_entries:
        for ref in container.get("references", []):
            for tag in ref.get("tags", []):
                if isinstance(tag, str) and tag:
                    tags.add(tag)
    return sorted(tags)


def _extract_cwes(problem_types: list[dict]) -> list[CWE]:
    """
    Extract the CWEs from the problem types.

    :param problem_types: The list of problem types.
    :type problem_types: list[dict]
    :return: The list of CWEs.
    :rtype: list[CWE]
    """
    cwes: list[CWE] = []
    seen: set[str] = set()
    for problem_type in problem_types:
        for desc in problem_type.get("descriptions", []):
            cwe_id = str(desc.get("cweId", "")).strip()
            description = str(desc.get("description", "")).strip()
            if not cwe_id:
                match = re.search(r"(CWE-\d+)", description)
                if match:
                    cwe_id = match.group(1)
            if not cwe_id or cwe_id in seen:
                continue
            seen.add(cwe_id)
            cwes.append(CWE(cwe_id=cwe_id, description=description))
    return cwes


def _extract_cvss_scores(container_entries: list[dict]) -> list[CVSS]:
    """
    Extract the CVSS scores from the container entries.

    :param container_entries: The list of container entries.
    :type container_entries: list[dict]
    :return: The list of CVSS scores.
    :rtype: list[CVSS]
    """
    cvss_scores: list[CVSS] = []
    seen_vectors: set[str] = set()
    for container in container_entries:
        metrics = container.get("metrics", [])
        if not isinstance(metrics, list):
            continue
        for metric in metrics:
            for version_label, block in _iter_cvss_metric_blocks(metric):
                vector = str(block.get("vectorString", "")).strip()
                if vector and vector in seen_vectors:
                    continue
                if vector:
                    seen_vectors.add(vector)
                score = float(block.get("baseScore", 0.0) or 0.0)
                severity = severity_from_cvss_base(block.get("baseSeverity"), score)
                cvss_scores.append(
                    CVSS(
                        version=version_label,
                        score=score,
                        vector=vector,
                        severity=severity,
                        attack_vector=str(block.get("attackVector", "")).strip(),
                        attack_complexity=str(
                            block.get("attackComplexity", "")
                        ).strip(),
                        privileges_required=str(
                            block.get("privilegesRequired", "")
                        ).strip(),
                        user_interaction=str(block.get("userInteraction", "")).strip(),
                        scope=str(block.get("scope", "")).strip(),
                        confidentiality=str(
                            block.get("confidentialityImpact", "")
                        ).strip(),
                        integrity=str(block.get("integrityImpact", "")).strip(),
                        availability=str(block.get("availabilityImpact", "")).strip(),
                    )
                )
    return cvss_scores


def _iter_cvss_metric_blocks(metric: dict) -> list[tuple[str, dict]]:
    """
    Iterate over the CVSS metric blocks.

    :param metric: The CVSS metric.
    :type metric: dict
    :return: The list of CVSS metric blocks.
    :rtype: list[tuple[str, dict]]
    """
    blocks: list[tuple[str, dict]] = []
    for key, version in (("cvssV3_0", "3.0"), ("cvssV3_1", "3.1"), ("cvssV4_0", "4.0")):
        block = metric.get(key)
        if isinstance(block, dict):
            blocks.append((version, block))
    return blocks


def _get_years() -> list[int]:
    """
    Get the years from the CVEProject.

    :return: The years from the CVEProject.
    :rtype: list[int]
    """
    years = [int(d.stem) for d in CVE_DIRECTORY.iterdir() if d.is_dir()]
    years.sort()
    return years


async def _download_and_unpack_cve_zip() -> bool:
    """
    Download the CVE list from CVEProject.

    :return: True if the CVE list was downloaded successfully, False otherwise.
    :rtype: bool
    """

    if LOCAL_ZIP_PATH.is_file():
        logger.info(f"Using existing zip file {LOCAL_ZIP_PATH}")
    else:
        if not await download_zip(ZIP_URL, str(LOCAL_ZIP_PATH)):
            return False

    if not _unzip_file(LOCAL_ZIP_PATH, UNZIPPED_PATH):
        return False

    inner_zip = UNZIPPED_PATH / "cves.zip"
    if not inner_zip.is_file():
        logger.error(
            f"Expected nested {inner_zip} after extracting release zip; "
            f"got {sorted(p.name for p in UNZIPPED_PATH.iterdir())}"
        )
        return False

    return _unzip_file(inner_zip, UNZIPPED_PATH)


def _unzip_file(zip_path: Path, output_path: Path) -> bool:
    """
    Unzip a file.

    :param zip_path: The path to the zip file.
    :type zip_path: Path
    :param output_path: The path to the output directory.
    :type output_path: Path
    :return: True if the file was unzipped successfully, False otherwise.
    :rtype: bool
    """

    output_path.mkdir(parents=True, exist_ok=True)

    try:
        with ZipFile(zip_path, "r") as zip_ref:
            members = zip_ref.infolist()
            for member in tqdm(
                members,
                desc=f"Extract {zip_path.name}",
                unit="file",
                leave=True,
            ):
                zip_ref.extract(member, output_path)
        logger.info(f"Unzipped file {zip_path} to {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to unzip file {zip_path}: {e}")
        return False
