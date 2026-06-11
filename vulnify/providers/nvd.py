"""NVD CVE API 2.0 — CVSS lineage, CWE, CPE, references, optional CISA echo fields."""

from __future__ import annotations

import re
import sqlite3
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import urlencode

from loguru import logger

from vulnify.constants import SourceTrust
from vulnify.cvss_severity import severity_from_cvss_base
from vulnify.db.sql_conversion import bool_to_sql
from vulnify.http import fetch_json_maybe
from vulnify.settings import get_nvd_api_key
from vulnify.models.cpe import CpeMatch
from vulnify.models.cve import CVE
from vulnify.models.cvss import CVSS
from vulnify.models.cwe import CWE
from vulnify.models.kev import KEVStatus
from vulnify.models.reference import Reference

NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Transient disconnects / 5xx / 429: retry before treating as missing data.
NVD_FETCH_MAX_ATTEMPTS = 5

# NVD 2.0 caps a single ``/cves/2.0`` page at 2000 records.
NVD_BULK_RESULTS_PER_PAGE = 2000

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _parse_iso_date(value: str | None) -> date:
    """
    Parse a YYYY-MM-DD prefix from an ISO date or datetime string.

    :param value: The date string.
    :type value: str | None
    :return: The parsed date, or :attr:`datetime.date.min` when invalid.
    :rtype: date
    """
    parts = (value or "").strip()[:10].split("-")
    if len(parts) != 3:
        return date.min
    try:
        return date(int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return date.min


def _parse_nvd_datetime(value: str | None) -> datetime | None:
    """
    Parse an NVD datetime.

    :param value: The NVD datetime string.
    :type value: str | None
    :return: The parsed datetime, or None when the string is invalid.
    :rtype: datetime | None
    """
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _extract_cvss_v31_blocks(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract CVSS v3.1 blocks from the metrics.

    :param metrics: The metrics.
    :type metrics: dict[str, Any]
    :return: The extracted CVSS v3.1 blocks.
    :rtype: list[dict[str, Any]]
    """
    out: list[dict[str, Any]] = []
    for key in ("cvssMetricV31",):
        block_list = metrics.get(key)
        if isinstance(block_list, list):
            out.extend(b for b in block_list if isinstance(b, dict))
    return out


def _extract_cvss_v30_blocks(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract CVSS v3.0 blocks from the metrics.

    :param metrics: The metrics.
    :type metrics: dict[str, Any]
    :return: The extracted CVSS v3.0 blocks.
    :rtype: list[dict[str, Any]]
    """
    out: list[dict[str, Any]] = []
    for key in ("cvssMetricV30",):
        block_list = metrics.get(key)
        if isinstance(block_list, list):
            out.extend(b for b in block_list if isinstance(b, dict))
    return out


def _cvss_from_nvd_block(
    block: dict[str, Any],
    version: str,
) -> CVSS | None:
    """
    Extract a CVSS block from the metrics.

    :param block: The block.
    :type block: dict[str, Any]
    :param version: The version.
    :type version: str
    :return: The extracted CVSS block.
    :rtype: CVSS | None
    """
    data = block.get("cvssData")
    if not isinstance(data, dict):
        return None
    vector = str(data.get("vectorString", "")).strip()
    score = float(data.get("baseScore") or 0.0)
    src = str(block.get("source", "")).strip()
    mtype = str(block.get("type", "")).strip()
    expl = block.get("exploitabilityScore")
    impact = block.get("impactScore")
    return CVSS(
        version=version,
        score=score,
        vector=vector,
        severity=severity_from_cvss_base(data.get("baseSeverity"), score),
        attack_vector=str(data.get("attackVector", "") or ""),
        attack_complexity=str(data.get("attackComplexity", "") or ""),
        privileges_required=str(data.get("privilegesRequired", "") or ""),
        user_interaction=str(data.get("userInteraction", "") or ""),
        scope=str(data.get("scope", "") or ""),
        confidentiality=str(data.get("confidentialityImpact", "") or ""),
        integrity=str(data.get("integrityImpact", "") or ""),
        availability=str(data.get("availabilityImpact", "") or ""),
        metric_source=src,
        metric_type=mtype,
        exploitability_score=float(expl) if expl is not None else 0.0,
        impact_score=float(impact) if impact is not None else 0.0,
    )


def _collect_cpe_matches(configurations: list[dict[str, Any]]) -> list[CpeMatch]:
    """
    Collect CPE matches from the configurations.

    NVD often repeats the same ``(criteria, matchCriteriaId)`` pair across
    multiple ``configurations[].nodes`` (one entry per AND-clause it appears
    in). Dedupe on that key so the merged ``cpe_match`` table doesn't grow
    redundant rows.

    :param configurations: The configurations.
    :type configurations: list[dict[str, Any]]
    :return: The collected CPE matches.
    :rtype: list[CpeMatch]
    """
    matches: list[CpeMatch] = []
    seen: set[tuple[str, str]] = set()
    for conf in configurations:
        if not isinstance(conf, dict):
            continue
        nodes = conf.get("nodes") or []
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            cpe_match = node.get("cpeMatch") or []
            if not isinstance(cpe_match, list):
                continue
            for m in cpe_match:
                if not isinstance(m, dict):
                    continue
                crit = str(m.get("criteria", "")).strip()
                if not crit:
                    continue
                mid = str(m.get("matchCriteriaId", "") or "").strip()
                key = (crit, mid)
                if key in seen:
                    continue
                seen.add(key)
                vuln = m.get("vulnerable", True)
                matches.append(
                    CpeMatch(
                        criteria=crit,
                        match_criteria_id=mid,
                        vulnerable=bool(vuln),
                    )
                )
    return matches


def _merge_weaknesses_into_cwes(cve: CVE, weaknesses: list[dict[str, Any]]) -> None:
    """
    Merge weaknesses into CWEs.

    :param cve: The CVE.
    :type cve: CVE
    :param weaknesses: The weaknesses.
    :type weaknesses: list[dict[str, Any]]
    """
    seen = {c.cwe_id.upper() for c in cve.cwes if c.cwe_id}
    for w in weaknesses:
        if not isinstance(w, dict):
            continue
        for desc in w.get("description") or []:
            if not isinstance(desc, dict):
                continue
            if str(desc.get("lang", "")).lower() not in {"", "en"}:
                continue
            raw = str(desc.get("value", "")).strip()
            m = _CWE_RE.search(raw)
            cid = m.group(0).upper() if m else ""
            if not cid or cid in seen:
                continue
            seen.add(cid)
            cve.cwes.append(CWE(cwe_id=cid, name="", description=raw))


def _append_references_nvd(cve: CVE, references: list[dict[str, Any]]) -> None:
    """
    Append references from NVD to the CVE.

    :param cve: The CVE.
    :type cve: CVE
    :param references: The references.
    :type references: list[dict[str, Any]]
    """
    have = {r.url for r in cve.references}
    for ref in references:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url", "")).strip()
        if not url or url in have:
            continue
        have.add(url)
        tags = [
            str(t).strip()
            for t in (ref.get("tags") or [])
            if isinstance(t, str) and t.strip()
        ]
        trust = (
            SourceTrust.VENDOR
            if any("Vendor Advisory" == t for t in tags)
            else SourceTrust.COMMUNITY
        )
        cve.references.append(
            Reference(
                url=url,
                source=str(ref.get("source", "") or "").strip() or "nvd",
                title="",
                tags=tags,
                trust=trust,
            )
        )


def _cvss_dedup_key(c: CVSS) -> tuple[str, str, str]:
    """
    Get the CVSS dedup key.

    :param c: The CVSS.
    :type c: CVSS
    :return: The CVSS dedup key.
    :rtype: tuple[str, str, str]
    """
    return (c.vector or "", c.metric_source or "", c.metric_type or "")


def merge_nvd_cve_document(cve: CVE, nvd_cve: dict[str, Any]) -> None:
    """
    Merge a single NVD ``cve`` object (from ``vulnerabilities[].cve``) into ``cve``.

    Does not overwrite KEV rows sourced from CISA (``cve.kev.source == \"cisa\"``).
    """
    cve.vuln_status = str(nvd_cve.get("vulnStatus", "") or "").strip()
    cve.source_identifier = str(nvd_cve.get("sourceIdentifier", "") or "").strip()

    lm = _parse_nvd_datetime(nvd_cve.get("lastModified"))
    if lm and lm.tzinfo is None:
        lm = lm.replace(tzinfo=timezone.utc)
    if lm and lm > cve.modified.replace(tzinfo=cve.modified.tzinfo or timezone.utc):
        cve.modified = lm

    metrics = nvd_cve.get("metrics")
    if isinstance(metrics, dict):
        new_scores: list[CVSS] = []
        for block in _extract_cvss_v31_blocks(metrics):
            cv = _cvss_from_nvd_block(block, "3.1")
            if cv:
                new_scores.append(cv)
        for block in _extract_cvss_v30_blocks(metrics):
            cv = _cvss_from_nvd_block(block, "3.0")
            if cv:
                new_scores.append(cv)
        existing_keys = {_cvss_dedup_key(c) for c in cve.cvss_scores}
        for cv in new_scores:
            k = _cvss_dedup_key(cv)
            if k not in existing_keys:
                existing_keys.add(k)
                cve.cvss_scores.append(cv)

    weaknesses = nvd_cve.get("weaknesses")
    if isinstance(weaknesses, list):
        _merge_weaknesses_into_cwes(cve, weaknesses)

    configurations = nvd_cve.get("configurations")
    if isinstance(configurations, list):
        new_cpes = _collect_cpe_matches(configurations)
        if new_cpes:
            cve.cpe_matches = new_cpes

    refs = nvd_cve.get("references")
    if isinstance(refs, list):
        _append_references_nvd(cve, refs)

    cisa_add = nvd_cve.get("cisaExploitAdd")
    if cisa_add and (cve.kev.source or "").lower() != "cisa":
        cve.kev = KEVStatus(
            listed=True,
            date_added=_parse_iso_date(str(cisa_add)),
            due_date=_parse_iso_date(str(nvd_cve.get("cisaActionDue") or "")),
            notes=str(nvd_cve.get("cisaRequiredAction", "") or ""),
            vulnerability_name=str(nvd_cve.get("cisaVulnerabilityName", "") or ""),
            source="nvd",
        )
        cve.exploit.in_the_wild = True


async def fetch_nvd_cve_json(cve_id: str) -> tuple[dict[str, Any], str | None]:
    """
    Fetch a NVD CVE JSON.

    :param cve_id: The CVE ID.
    :type cve_id: str
    :return: ``(document, None)`` on HTTP success, or ``({}, error_detail)``.
    :rtype: tuple[dict[str, Any], str | None]
    """
    params = {"cveId": (cve_id or "").strip()}
    url = f"{NVD_CVES_URL}?{urlencode(params)}"
    extra_headers: dict[str, str] | None = None
    key = get_nvd_api_key()
    if key:
        extra_headers = {"apiKey": key}
    data, err = await fetch_json_maybe(
        url,
        max_attempts=NVD_FETCH_MAX_ATTEMPTS,
        extra_headers=extra_headers,
    )
    if err is not None:
        return {}, err
    if not isinstance(data, dict):
        return {}, "invalid NVD payload"
    return data, None


async def fetch_nvd_page(
    start_index: int,
    *,
    results_per_page: int = NVD_BULK_RESULTS_PER_PAGE,
    last_mod_start_date: str | None = None,
    last_mod_end_date: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    """
    Fetch one page of the NVD 2.0 ``/cves/2.0`` listing.

    The 2.0 API returns up to ``results_per_page`` (capped at 2000) full
    CVE records per call. Iterating ``start_index`` in increments of the
    page size walks the entire listing without a per-CVE round-trip — the
    public throttle (5 req / 30s without a key) lets the whole dataset
    pull in well under an hour rather than weeks.

    :param start_index: Zero-based offset into the global CVE list.
    :type start_index: int
    :param results_per_page: Page size; NVD caps this at 2000.
    :type results_per_page: int
    :param last_mod_start_date: Optional ISO 8601 lower bound on
        ``lastModified`` for incremental refresh; pair with
        ``last_mod_end_date``. NVD enforces a 120-day window.
    :type last_mod_start_date: str | None
    :param last_mod_end_date: Optional ISO 8601 upper bound on
        ``lastModified``.
    :type last_mod_end_date: str | None
    :return: ``(document, None)`` on HTTP success, or ``({}, error_detail)``
        on permanent failure.
    :rtype: tuple[dict[str, Any], str | None]
    """
    params: dict[str, Any] = {
        "resultsPerPage": int(results_per_page),
        "startIndex": int(start_index),
    }
    if last_mod_start_date:
        params["lastModStartDate"] = last_mod_start_date
    if last_mod_end_date:
        params["lastModEndDate"] = last_mod_end_date
    url = f"{NVD_CVES_URL}?{urlencode(params)}"
    extra_headers: dict[str, str] | None = None
    key = get_nvd_api_key()
    if key:
        extra_headers = {"apiKey": key}
    data, err = await fetch_json_maybe(
        url,
        max_attempts=NVD_FETCH_MAX_ATTEMPTS,
        extra_headers=extra_headers,
    )
    if err is not None:
        return {}, err
    if not isinstance(data, dict):
        return {}, "invalid NVD payload"
    return data, None


def merge_nvd_cve_into_db(conn: sqlite3.Connection, nvd_cve: dict[str, Any]) -> bool:
    """
    Merge a single NVD ``cve`` object directly into the SQLite store.

    Skips the full :class:`~vulnify.models.cve.CVE` round-trip that the
    :func:`merge_nvd_cve_document` + :meth:`SqliteCveStore.upsert_cve` path
    requires — at 347k CVE rows that round-trip is the dominant cost of an
    initial backfill. The writes here are idempotent on every column they
    touch:

    * ``cve.vuln_status`` / ``source_identifier`` / ``modified`` are
      ``UPDATE``\\ d in place; ``modified`` only advances when NVD's
      ``lastModified`` is newer.
    * ``cvss`` rows are deduped by ``(vector, metric_source, metric_type)``.
    * ``cwe`` + ``cve_cwe`` use ``ON CONFLICT DO NOTHING``.
    * ``cpe_match`` is replaced wholesale (NVD owns this list).
    * ``reference`` rows dedupe by ``(cve_id, url)``.
    * ``kev`` / ``exploit`` are touched only when NVD echoes
      ``cisaExploitAdd`` and the existing KEV row isn't already
      ``source='cisa'``.

    :param conn: An open SQLite connection (FK enforcement honoured).
    :type conn: sqlite3.Connection
    :param nvd_cve: The ``vulnerabilities[].cve`` object from NVD.
    :type nvd_cve: dict[str, Any]
    :return: True when the CVE existed in the local store and was updated.
    :rtype: bool
    """
    cve_id = str(nvd_cve.get("id", "") or "").strip()
    if not cve_id:
        return False

    cur = conn.cursor()
    cur.execute("SELECT modified FROM cve WHERE cve_id = ? LIMIT 1", (cve_id,))
    row = cur.fetchone()
    if row is None:
        return False
    existing_modified = "" if row[0] is None else str(row[0])

    vuln_status = str(nvd_cve.get("vulnStatus", "") or "").strip()
    source_identifier = str(nvd_cve.get("sourceIdentifier", "") or "").strip()

    nvd_lm = _parse_nvd_datetime(nvd_cve.get("lastModified"))
    if nvd_lm is not None and nvd_lm.tzinfo is None:
        nvd_lm = nvd_lm.replace(tzinfo=timezone.utc)
    nvd_lm_str = nvd_lm.isoformat() if nvd_lm else ""

    if nvd_lm_str and (not existing_modified or nvd_lm_str > existing_modified):
        cur.execute(
            "UPDATE cve "
            "SET vuln_status = ?, source_identifier = ?, modified = ? "
            "WHERE cve_id = ?",
            (vuln_status, source_identifier, nvd_lm_str, cve_id),
        )
    else:
        cur.execute(
            "UPDATE cve SET vuln_status = ?, source_identifier = ? WHERE cve_id = ?",
            (vuln_status, source_identifier, cve_id),
        )

    metrics = nvd_cve.get("metrics")
    if isinstance(metrics, dict):
        cur.execute(
            "SELECT vector, metric_source, metric_type FROM cvss WHERE cve_id = ?",
            (cve_id,),
        )
        existing_cvss_keys = {
            (
                "" if r[0] is None else str(r[0]),
                "" if r[1] is None else str(r[1]),
                "" if r[2] is None else str(r[2]),
            )
            for r in cur.fetchall()
        }
        new_blocks: list[tuple[dict[str, Any], str]] = [
            (b, "3.1") for b in _extract_cvss_v31_blocks(metrics)
        ]
        new_blocks.extend((b, "3.0") for b in _extract_cvss_v30_blocks(metrics))
        for block, ver in new_blocks:
            cv = _cvss_from_nvd_block(block, ver)
            if cv is None:
                continue
            key = (cv.vector or "", cv.metric_source or "", cv.metric_type or "")
            if key in existing_cvss_keys:
                continue
            existing_cvss_keys.add(key)
            cur.execute(
                """
                INSERT INTO cvss (
                    cve_id, version, score, vector, severity,
                    attack_vector, attack_complexity, privileges_required,
                    user_interaction, scope,
                    confidentiality, integrity, availability,
                    metric_source, metric_type,
                    exploitability_score, impact_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    cv.version or "",
                    float(cv.score),
                    cv.vector or "",
                    cv.severity.value,
                    cv.attack_vector or "",
                    cv.attack_complexity or "",
                    cv.privileges_required or "",
                    cv.user_interaction or "",
                    cv.scope or "",
                    cv.confidentiality or "",
                    cv.integrity or "",
                    cv.availability or "",
                    cv.metric_source or "",
                    cv.metric_type or "",
                    float(cv.exploitability_score),
                    float(cv.impact_score),
                ),
            )

    weaknesses = nvd_cve.get("weaknesses")
    if isinstance(weaknesses, list):
        for w in weaknesses:
            if not isinstance(w, dict):
                continue
            for desc in w.get("description") or []:
                if not isinstance(desc, dict):
                    continue
                if str(desc.get("lang", "")).lower() not in {"", "en"}:
                    continue
                raw = str(desc.get("value", "") or "").strip()
                m = _CWE_RE.search(raw)
                if not m:
                    continue
                cwe_id = m.group(0).upper()
                cur.execute(
                    "INSERT INTO cwe (cwe_id, name, description) "
                    "VALUES (?, '', ?) "
                    "ON CONFLICT(cwe_id) DO NOTHING",
                    (cwe_id, raw),
                )
                cur.execute(
                    "INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (?, ?)",
                    (cve_id, cwe_id),
                )

    configurations = nvd_cve.get("configurations")
    if isinstance(configurations, list):
        new_cpes = _collect_cpe_matches(configurations)
        if new_cpes:
            cur.execute("DELETE FROM cpe_match WHERE cve_id = ?", (cve_id,))
            cur.executemany(
                "INSERT INTO cpe_match "
                "(cve_id, criteria, match_criteria_id, vulnerable) "
                "VALUES (?, ?, ?, ?)",
                [
                    (
                        cve_id,
                        cm.criteria,
                        cm.match_criteria_id or "",
                        bool_to_sql(cm.vulnerable),
                    )
                    for cm in new_cpes
                ],
            )

    refs = nvd_cve.get("references")
    if isinstance(refs, list):
        cur.execute("SELECT url FROM reference WHERE cve_id = ?", (cve_id,))
        existing_urls = {"" if r[0] is None else str(r[0]) for r in cur.fetchall()}
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            url = str(ref.get("url", "") or "").strip()
            if not url or url in existing_urls:
                continue
            existing_urls.add(url)
            tags = [
                str(t).strip()
                for t in (ref.get("tags") or [])
                if isinstance(t, str) and t.strip()
            ]
            trust = (
                SourceTrust.VENDOR
                if any(t == "Vendor Advisory" for t in tags)
                else SourceTrust.COMMUNITY
            )
            source = str(ref.get("source", "") or "").strip() or "nvd"
            cur.execute(
                "INSERT INTO reference (cve_id, url, source, title, trust) "
                "VALUES (?, ?, ?, '', ?)",
                (cve_id, url, source, trust.value),
            )
            ref_id = int(cur.lastrowid)
            for tag in tags:
                cur.execute(
                    "INSERT OR IGNORE INTO reference_tag (reference_id, tag) "
                    "VALUES (?, ?)",
                    (ref_id, tag),
                )

    cisa_add = nvd_cve.get("cisaExploitAdd")
    if cisa_add:
        cur.execute("SELECT source FROM kev WHERE cve_id = ?", (cve_id,))
        krow = cur.fetchone()
        existing_kev_source = (
            "" if krow is None or krow[0] is None else str(krow[0])
        ).lower()
        if existing_kev_source != "cisa":
            date_added = _parse_iso_date(str(cisa_add))
            due_date = _parse_iso_date(str(nvd_cve.get("cisaActionDue") or ""))
            cur.execute(
                """
                INSERT INTO kev (
                    cve_id, listed, date_added, due_date, notes,
                    vulnerability_name, required_action, source
                ) VALUES (?, 1, ?, ?, ?, ?, '', 'nvd')
                ON CONFLICT(cve_id) DO UPDATE SET
                    listed = 1,
                    date_added = excluded.date_added,
                    due_date = excluded.due_date,
                    notes = excluded.notes,
                    vulnerability_name = excluded.vulnerability_name,
                    source = 'nvd'
                """,
                (
                    cve_id,
                    date_added.isoformat() if date_added != date.min else "",
                    due_date.isoformat() if due_date != date.min else "",
                    str(nvd_cve.get("cisaRequiredAction", "") or ""),
                    str(nvd_cve.get("cisaVulnerabilityName", "") or ""),
                ),
            )
            cur.execute(
                "INSERT INTO exploit (cve_id, in_the_wild) VALUES (?, 1) "
                "ON CONFLICT(cve_id) DO UPDATE SET in_the_wild = 1",
                (cve_id,),
            )

    return True


async def enrich_cve_from_nvd(cve: CVE) -> bool:
    """
    Fetch NVD for ``cve.cve_id`` and merge into ``cve`` in place.

    :return: True if NVD returned a vulnerability record.
    :rtype: bool
    """
    raw, fetch_err = await fetch_nvd_cve_json(cve.cve_id)
    if fetch_err is not None:
        logger.warning(
            "NVD: request failed for {cve_id} after retries: {detail}",
            cve_id=cve.cve_id,
            detail=fetch_err,
        )
        return False
    vulns = raw.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        logger.debug(f"NVD: no CVE record in response for {cve.cve_id}")
        return False
    first = vulns[0]
    if not isinstance(first, dict):
        return False
    nvd_cve = first.get("cve")
    if not isinstance(nvd_cve, dict):
        return False
    merge_nvd_cve_document(cve, nvd_cve)
    return True


__all__ = [
    "NVD_BULK_RESULTS_PER_PAGE",
    "NVD_CVES_URL",
    "NVD_FETCH_MAX_ATTEMPTS",
    "enrich_cve_from_nvd",
    "fetch_nvd_cve_json",
    "fetch_nvd_page",
    "merge_nvd_cve_into_db",
    "merge_nvd_cve_document",
]
