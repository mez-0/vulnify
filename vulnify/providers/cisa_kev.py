"""CISA Known Exploited Vulnerabilities catalog (JSON feed or local snapshot)."""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path

from loguru import logger
from tqdm import tqdm

from vulnify.constants import SourceTrust
from vulnify.db.pipeline_state import get_phase_state, set_phase_state
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.cve import CVE
from vulnify.models.cwe import CWE
from vulnify.models.exploit import ExploitInfo
from vulnify.models.kev import KEVStatus
from vulnify.models.reference import Reference
from vulnify.models.vendor import Vendor
from vulnify.settings import get_kev_catalog_path

KEV_PIPELINE_PHASE = "kev"


def _parse_iso_date(s: str | None) -> date:
    """
    Parse an ISO date.

    :param s: The ISO date string.
    :type s: str | None
    :return: The parsed date, or the minimum date when the string is invalid.
    :rtype: date
    """
    parts = (s or "").strip()[:10].split("-")
    if len(parts) != 3:
        return date.min
    try:
        return date(int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return date.min


def _ransomware_from_kev(value: str | None) -> bool:
    """
    Check if the value is a ransomware.

    :param value: The value to check.
    :type value: str | None
    :return: True if the value is a ransomware, False otherwise.
    :rtype: bool
    """
    return (value or "").strip().lower() == "yes"


def _references_from_notes(notes: str | None) -> list[Reference]:
    """
    Get the references from the notes.

    :param notes: The notes to get the references from.
    :type notes: str | None
    :return: The references from the notes.
    :rtype: list[Reference]
    """
    if not notes:
        return []
    parts = [p.strip() for p in notes.replace("\n", ";").split(";")]
    out: list[Reference] = []
    for p in parts:
        if not p or not p.startswith("http"):
            continue
        out.append(
            Reference(
                url=p,
                source="cisa-kev",
                title="",
                tags=[],
                trust=SourceTrust.CISA,
            )
        )
    return out


def _merge_kev_cwes(cve: CVE, cwe_ids: list[str]) -> None:
    """
    Merge the KEV CWEs into the CVE.

    :param cve: The CVE to merge the KEV CWEs into.
    :type cve: CVE
    :param cwe_ids: The KEV CWEs to merge into the CVE.
    :type cwe_ids: list[str]
    """
    seen = {c.cwe_id.upper() for c in cve.cwes if c.cwe_id}
    for raw in cwe_ids:
        cid = (raw or "").strip().upper()
        if not cid.startswith("CWE-"):
            continue
        if cid in seen:
            continue
        seen.add(cid)
        cve.cwes.append(CWE(cwe_id=cid, name="", description=""))


def apply_cisa_kev_entry(cve: CVE, entry: dict) -> None:
    """
    Merge one KEV catalog entry into ``cve`` (CISA is authoritative for KEV fields).

    :param cve: The CVE to merge the KEV entry into.
    :type cve: CVE
    :param entry: The KEV entry to merge into the CVE.
    :type entry: dict
    """
    cve_id = str(entry.get("cveID", "") or "").strip()
    if cve_id and cve.cve_id != cve_id:
        cve.cve_id = cve_id

    vname = str(entry.get("vulnerabilityName", "") or "").strip()
    short = str(entry.get("shortDescription", "") or "").strip()
    vendor_p = str(entry.get("vendorProject", "") or "").strip()
    product_l = str(entry.get("product", "") or "").strip()

    if vname:
        cve.title = vname
    if short:
        cve.summary = short
        cve.technical_details = short

    notes_urls = str(entry.get("notes", "") or "").strip()
    req = str(entry.get("requiredAction", "") or "").strip()

    cve.kev = KEVStatus(
        listed=True,
        date_added=_parse_iso_date(entry.get("dateAdded")),
        due_date=_parse_iso_date(entry.get("dueDate")),
        notes=notes_urls,
        vulnerability_name=vname,
        required_action=req,
        vendor_project=vendor_p,
        product_label=product_l,
        short_description=short,
        source="cisa",
    )

    cve.exploit = ExploitInfo(
        maturity=cve.exploit.maturity,
        public_poc=cve.exploit.public_poc,
        metasploit=cve.exploit.metasploit,
        ransomware_usage=_ransomware_from_kev(entry.get("knownRansomwareCampaignUse")),
        in_the_wild=True,
        notes=cve.exploit.notes,
    )

    cwes_raw = entry.get("cwes")
    if isinstance(cwes_raw, list):
        _merge_kev_cwes(cve, [str(x) for x in cwes_raw])

    have_urls = {r.url for r in cve.references}
    for pref in _references_from_notes(entry.get("notes")):
        if pref.url not in have_urls:
            have_urls.add(pref.url)
            cve.references.append(pref)

    if vendor_p and not (cve.primary_vendor.name or "").strip():
        cve.primary_vendor = Vendor(name=vendor_p)


def cisa_entry_to_stub_cve(entry: dict) -> CVE:
    """
    Build a minimal CVE when the ID is not yet in the database.

    :param entry: The KEV entry to build the CVE from.
    :type entry: dict
    :return: The minimal CVE.
    :rtype: CVE
    """
    cid = str(entry.get("cveID", "") or "").strip()
    short = str(entry.get("shortDescription", "") or "").strip()
    vname = str(entry.get("vulnerabilityName", "") or "").strip()
    vendor_p = str(entry.get("vendorProject", "") or "").strip()
    cve = CVE(
        cve_id=cid,
        title=vname,
        summary=short,
        technical_details=short,
        primary_vendor=Vendor(name=vendor_p) if vendor_p else Vendor(),
        published=datetime.min.replace(tzinfo=timezone.utc),
        modified=datetime.min.replace(tzinfo=timezone.utc),
        discovered=datetime.min.replace(tzinfo=timezone.utc),
        references=_references_from_notes(entry.get("notes")),
    )
    apply_cisa_kev_entry(cve, entry)
    return cve


def load_kev_catalog(path: Path) -> dict:
    """
    Load the KEV catalog from the path.

    :param path: The path to load the KEV catalog from.
    :type path: Path
    :return: The KEV catalog.
    :rtype: dict
    """
    return json.loads(path.read_text(encoding="utf-8"))


async def ingest_cisa_kev_catalog(
    store: SqliteCveStore,
    *,
    catalog_path: Path | None = None,
    force: bool = False,
) -> int:
    """
    Upsert KEV rows for every entry in the CISA catalog.

    :param store: The SQLite store to upsert the KEV rows into.
    :type store: SqliteCveStore
    :param catalog_path: The path to the KEV catalog.
    :type catalog_path: Path | None
    :param force: Ingest even when the catalog version matches the watermark.
        Set when ingestion ran: the cascade wiped the ``kev`` rows, so an
        unchanged catalog is no reason to skip restoring them.
    :type force: bool
    :return: Number of entries processed.
    :rtype: int
    """

    path = catalog_path or get_kev_catalog_path()
    if path is None:
        logger.warning(
            "CISA KEV catalog not found (set VULNIFY_KEV_JSON_PATH or add "
            "known_exploited_vulnerabilities.json at project root)"
        )
        return 0

    data = load_kev_catalog(path)
    catalog_version = str(data.get("catalogVersion", "") or "").strip()

    _, last_version = get_phase_state(store.connection, KEV_PIPELINE_PHASE)
    if not force and catalog_version and last_version == catalog_version:
        logger.info(
            "CISA KEV: catalog unchanged (version={ver}); skipping ingest",
            ver=catalog_version,
        )
        return 0

    vulns = data.get("vulnerabilities")

    if not isinstance(vulns, list):
        return 0

    n = 0

    for entry in tqdm(vulns, desc="CISA KEV", unit="entry"):
        if not isinstance(entry, dict):
            continue

        cid = str(entry.get("cveID", "") or "").strip()

        if not cid:
            continue

        existing = store.get_cve(cid)

        if existing:
            apply_cisa_kev_entry(existing, entry)
            store.upsert_cve(existing)
        else:
            stub = cisa_entry_to_stub_cve(entry)
            store.upsert_cve(stub)

        n += 1

    completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    set_phase_state(
        store.connection,
        KEV_PIPELINE_PHASE,
        completed_at=completed_at,
        watermark=catalog_version or None,
    )
    store.connection.commit()

    logger.info(
        f"CISA KEV ingested {n} entries (catalogVersion={catalog_version!r})"
    )

    return n


__all__ = [
    "KEV_PIPELINE_PHASE",
    "apply_cisa_kev_entry",
    "cisa_entry_to_stub_cve",
    "ingest_cisa_kev_catalog",
    "load_kev_catalog",
]
