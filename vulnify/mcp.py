"""FastMCP server (``vulnify-mcp``) exposing the CVE SQLite DB to agents over stdio."""

from __future__ import annotations

import dataclasses
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any

import vulnify.settings  # noqa: F401 — load `.env` before other vulnify imports

from loguru import logger
from mcp.server.fastmcp import FastMCP

from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.settings import VULNIFY_SQLITE_PATH, get_sqlite_path_from_env

MCP_MAX_LIMIT = 100

# Sentinel values the CVE / KEV models use when a timestamp is unknown. Don't
# leak them back to agents (agents misread ``0001-01-01`` as a real date next
# to ``"listed": false``) — emit ``None`` instead.
_DATETIME_SENTINEL = datetime.min.replace(tzinfo=timezone.utc)
_DATE_SENTINEL = date.min

_store: SqliteCveStore | None = None

mcp = FastMCP("vulnify")


def _get_store() -> SqliteCveStore:
    """Open (or return the already-open) writable SqliteCveStore.

    Writable on purpose: the store runs additive migrations on init —
    including the FTS5 backfill against older release DBs. WAL mode means we
    won't block a parallel ``vulnify-gather`` writer.
    """
    global _store
    if _store is None:
        path = get_sqlite_path_from_env()
        if path is None:
            raise RuntimeError(
                f"{VULNIFY_SQLITE_PATH} is unset — set it in .env to point at the "
                "vulnify SQLite DB before starting the MCP server."
            )
        if not path.is_file():
            raise FileNotFoundError(
                f"SQLite DB not found at {path}. Run `vulnify-gather` to build "
                "it, or download the release asset and decompress it."
            )
        _store = SqliteCveStore(path)
    return _store


def _to_jsonable(obj: Any) -> Any:
    """Walk a value into JSON-serialisable primitives."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, datetime):
        if obj == _DATETIME_SENTINEL:
            return None
        return obj.isoformat()
    if isinstance(obj, date):
        if obj == _DATE_SENTINEL:
            return None
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj):
        return {
            f.name: _to_jsonable(getattr(obj, f.name))
            for f in dataclasses.fields(obj)
        }
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_to_jsonable(v) for v in obj]
    return str(obj)


def _row_to_summary(row: Any) -> dict[str, Any]:
    """Common summary-row shape used by all list-returning tools."""
    return {
        "cve_id": row["cve_id"],
        "title": row["title"],
        "summary": row["summary"],
        "published": row["published"],
        "max_cvss": row["max_cvss"],
        "severity": row["severity"],
        "epss_score": row["epss_score"],
        "kev_listed": bool(row["kev_listed"]),
    }


def _clamp_limit(limit: int) -> int:
    if limit < 1:
        return 1
    if limit > MCP_MAX_LIMIT:
        return MCP_MAX_LIMIT
    return limit


_ARTEFACT_COLUMNS = (
    "source",
    "stable_id",
    "url",
    "artefact_type",
    "platform",
    "published_date",
    "confidence",
)


def _exploit_artefacts(store: SqliteCveStore, cve_id: str) -> list[dict[str, Any]]:
    """Artefact rows for a CVE, shared by ``exploits_for`` and ``get_cve``.

    Returns ``[]`` for an unknown CVE or one whose exploit phases haven't run —
    a bare read of ``exploit_artefact`` with no dependence on the summary bools.
    """
    cur = store.connection.cursor()
    cur.execute(
        """
        SELECT source, stable_id, url, artefact_type, platform,
               published_date, confidence
        FROM exploit_artefact
        WHERE cve_id = ?
        ORDER BY source, stable_id
        """,
        (cve_id,),
    )
    return [{col: row[col] for col in _ARTEFACT_COLUMNS} for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def get_cve(cve_id: str) -> dict[str, Any] | None:
    """
    Fetch a fully hydrated CVE record by ID.

    Returns the CVE with all related entities — CVSS metrics, KEV listing,
    EPSS score, exploit signals, references, CWEs, vendors, affected
    products and CPE matches — plus an ``artefacts`` list of concrete exploit
    evidence (the same rows :func:`exploits_for` returns). Returns ``None`` if
    the CVE is unknown.

    Note on exploit signals: ``exploit.public_poc`` and ``exploit.metasploit``
    are tri-state. ``null`` means *not assessed* (the contributing exploit
    source has not completed a run yet) — it does **not** mean "no exploit
    exists"; ``false`` means assessed and none found. When assessed they are
    derived from ``artefacts``: ``public_poc`` from Nuclei + Exploit-DB,
    ``metasploit`` from Metasploit modules. Use ``artefacts`` for the evidence
    (source, url, confidence) behind each signal. ``exploit.in_the_wild`` and
    ``exploit.ransomware_usage`` come from NVD / CISA KEV.

    :param cve_id: Canonical CVE id, e.g. ``"CVE-2024-3094"``.
    """
    store = _get_store()
    cid = cve_id.strip().upper()
    cve = store.get_cve(cid)
    if cve is None:
        return None
    result = _to_jsonable(cve)
    result["artefacts"] = _exploit_artefacts(store, cid)
    return result


@mcp.tool()
def search_cves(
    vendor: str | None = None,
    product: str | None = None,
    cwe: str | None = None,
    kev_only: bool = False,
    min_cvss: float | None = None,
    min_epss: float | None = None,
    year: int | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """
    Filter CVEs by structured criteria. All parameters are optional; the
    response is ordered by ``published DESC``.

    :param vendor: Case-insensitive substring match on vendor name.
    :param product: Case-insensitive substring match on product name.
    :param cwe: Exact CWE id, e.g. ``"CWE-79"``.
    :param kev_only: If True, only CVEs listed in CISA KEV.
    :param min_cvss: Minimum max-CVSS score (any version).
    :param min_epss: Minimum EPSS probability (0.0–1.0).
    :param year: Restrict to CVEs published in this year.
    :param limit: Max rows to return (1–100).
    """
    store = _get_store()
    limit = _clamp_limit(limit)

    joins: list[str] = []
    where: list[str] = []
    params: list[Any] = []

    if vendor:
        joins.append("JOIN cve_vendor cv ON cv.cve_id = c.cve_id")
        joins.append("JOIN vendor v ON v.vendor_id = cv.vendor_id")
        where.append("lower(v.name) LIKE ?")
        params.append(f"%{vendor.lower()}%")
    if product:
        joins.append("JOIN affected_product ap ON ap.cve_id = c.cve_id")
        joins.append("JOIN product p ON p.product_id = ap.product_id")
        where.append("lower(p.name) LIKE ?")
        params.append(f"%{product.lower()}%")
    if cwe:
        joins.append("JOIN cve_cwe cw ON cw.cve_id = c.cve_id")
        where.append("cw.cwe_id = ?")
        params.append(cwe.strip().upper())
    if kev_only:
        where.append("k.listed = 1")
    if min_cvss is not None:
        where.append(
            "EXISTS (SELECT 1 FROM cvss x WHERE x.cve_id = c.cve_id AND x.score >= ?)"
        )
        params.append(float(min_cvss))
    if min_epss is not None:
        where.append("i.epss_score >= ?")
        params.append(float(min_epss))
    if year is not None:
        where.append("substr(c.published, 1, 4) = ?")
        params.append(str(int(year)))

    join_sql = "\n".join(joins)
    where_sql = " AND ".join(where) if where else "1=1"

    sql = f"""
        SELECT DISTINCT
            c.cve_id,
            c.title,
            substr(c.summary, 1, 500) AS summary,
            c.published,
            (SELECT MAX(score) FROM cvss WHERE cve_id = c.cve_id) AS max_cvss,
            (SELECT severity FROM cvss WHERE cve_id = c.cve_id
                 ORDER BY score DESC LIMIT 1) AS severity,
            i.epss_score AS epss_score,
            COALESCE(k.listed, 0) AS kev_listed
        FROM cve c
        LEFT JOIN kev k ON k.cve_id = c.cve_id
        LEFT JOIN intel i ON i.cve_id = c.cve_id
        {join_sql}
        WHERE {where_sql}
        ORDER BY c.published DESC
        LIMIT ?
    """
    params.append(limit)

    cur = store.connection.cursor()
    cur.execute(sql, params)
    return [_row_to_summary(r) for r in cur.fetchall()]


@mcp.tool()
def list_kev(since: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """
    Recent CISA KEV catalog entries, newest ``date_added`` first.

    :param since: Optional ISO date (``YYYY-MM-DD``) — only entries listed
        on or after this date.
    :param limit: Max rows (1–100).
    """
    store = _get_store()
    limit = _clamp_limit(limit)

    where = "k.listed = 1"
    params: list[Any] = []
    if since:
        where += " AND substr(k.date_added, 1, 10) >= ?"
        params.append(since[:10])
    params.append(limit)

    sql = f"""
        SELECT
            k.cve_id, k.vendor_project, k.product_label,
            k.vulnerability_name, k.date_added, k.due_date,
            k.required_action, k.short_description, k.source,
            k.notes
        FROM kev k
        WHERE {where}
        ORDER BY k.date_added DESC, k.cve_id
        LIMIT ?
    """
    cur = store.connection.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    return [
        {
            "cve_id": r["cve_id"],
            "vendor_project": r["vendor_project"],
            "product_label": r["product_label"],
            "vulnerability_name": r["vulnerability_name"],
            "date_added": r["date_added"],
            "due_date": r["due_date"],
            "required_action": r["required_action"],
            "short_description": r["short_description"],
            "source": r["source"],
            "notes": r["notes"],
        }
        for r in rows
    ]


@mcp.tool()
def database_overview() -> dict[str, Any]:
    """Snapshot of the vulnify SQLite DB — totals + last pipeline-run times."""
    store = _get_store()
    cur = store.connection.cursor()

    cur.execute("SELECT COUNT(*) FROM cve")
    total_cves = int(cur.fetchone()[0])
    cur.execute("SELECT COUNT(*) FROM vendor WHERE trim(name) <> ''")
    total_vendors = int(cur.fetchone()[0])
    cur.execute("SELECT COUNT(*) FROM product")
    total_products = int(cur.fetchone()[0])
    cur.execute("SELECT COUNT(*) FROM kev WHERE listed = 1")
    total_kev = int(cur.fetchone()[0])
    cur.execute(
        "SELECT COUNT(*) FROM intel WHERE epss_score IS NOT NULL"
    )
    total_with_epss = int(cur.fetchone()[0])

    cur.execute("SELECT phase, last_completed_at FROM pipeline_run")
    pipeline_runs = {row["phase"]: row["last_completed_at"] for row in cur.fetchall()}

    cur.execute("SELECT MIN(published), MAX(published) FROM cve WHERE published <> ''")
    pub_min, pub_max = cur.fetchone()

    return {
        "db_path": str(store.path),
        "totals": {
            "cves": total_cves,
            "vendors": total_vendors,
            "products": total_products,
            "kev_listed": total_kev,
            "cves_with_epss": total_with_epss,
        },
        "published_range": {"min": pub_min, "max": pub_max},
        "pipeline_runs": pipeline_runs,
    }


@mcp.tool()
def search_cves_text(query: str, limit: int = 20) -> list[dict[str, Any]]:
    """
    Free-text search over CVE title, summary, and technical details.

    Uses SQLite FTS5 with Porter stemming. Bare words are AND-ed; use
    quoted phrases for exact strings, ``OR`` / ``NOT`` operators for
    boolean composition, ``*`` for prefix match (``"openssh*"``).

    :param query: FTS5 MATCH expression.
    :param limit: Max rows (1–100), ordered by BM25 relevance.
    """
    store = _get_store()
    limit = _clamp_limit(limit)

    sql = """
        SELECT
            c.cve_id,
            c.title,
            substr(c.summary, 1, 500) AS summary,
            c.published,
            (SELECT MAX(score) FROM cvss WHERE cve_id = c.cve_id) AS max_cvss,
            (SELECT severity FROM cvss WHERE cve_id = c.cve_id
                 ORDER BY score DESC LIMIT 1) AS severity,
            i.epss_score AS epss_score,
            COALESCE(k.listed, 0) AS kev_listed
        FROM cve_fts
        JOIN cve c ON c.rowid = cve_fts.rowid
        LEFT JOIN kev k ON k.cve_id = c.cve_id
        LEFT JOIN intel i ON i.cve_id = c.cve_id
        WHERE cve_fts MATCH ?
        ORDER BY rank
        LIMIT ?
    """
    cur = store.connection.cursor()
    cur.execute(sql, (query, limit))
    return [_row_to_summary(r) for r in cur.fetchall()]


@mcp.tool()
def exploits_for(cve_id: str) -> list[dict[str, Any]]:
    """
    Concrete exploit artefacts known for a CVE — the evidence behind the
    ``public_poc`` / ``metasploit`` summary signals.

    Each row carries ``source`` (``nuclei`` / ``exploitdb`` / ``metasploit``),
    ``stable_id`` (template id / ``EDB-<n>`` / module path), ``url``,
    ``artefact_type``, ``platform``, ``published_date``, and ``confidence`` —
    a provenance grade, not a quality score: ``exact`` (CVE id from a structured
    field) or ``parsed`` (extracted from a free-text field).

    Returns ``[]`` when no artefacts are recorded — which means either *none
    found* or *not yet assessed*; check ``get_cve``'s tri-state
    ``public_poc`` / ``metasploit`` to tell the two apart.

    :param cve_id: Canonical CVE id, e.g. ``"CVE-2021-44228"``.
    """
    store = _get_store()
    return _exploit_artefacts(store, cve_id.strip().upper())


@mcp.tool()
def references_for(cve_id: str, tag: str | None = None) -> list[dict[str, Any]]:
    """
    Reference URLs for a CVE, each with its tags, optionally filtered by tag.

    With ``tag`` set, returns only references carrying that tag (e.g.
    ``"patch"``, ``"exploit"``, ``"vendor-advisory"``); the full tag list is
    still included on each. Without it, returns every reference. Unknown CVE or
    no match → ``[]``.

    :param cve_id: Canonical CVE id, e.g. ``"CVE-2021-44228"``.
    :param tag: Optional reference tag to filter by (exact match).
    """
    store = _get_store()
    cid = cve_id.strip().upper()

    where = "r.cve_id = ?"
    params: list[Any] = [cid]
    if tag:
        where += (
            " AND r.id IN (SELECT reference_id FROM reference_tag WHERE tag = ?)"
        )
        params.append(tag)

    sql = f"""
        SELECT r.id, r.url, r.source, r.title, r.trust, rt.tag
        FROM reference r
        LEFT JOIN reference_tag rt ON rt.reference_id = r.id
        WHERE {where}
        ORDER BY r.id, rt.tag
    """
    cur = store.connection.cursor()
    cur.execute(sql, params)

    refs: dict[Any, dict[str, Any]] = {}
    order: list[Any] = []
    for row in cur.fetchall():
        rid = row["id"]
        if rid not in refs:
            refs[rid] = {
                "url": row["url"],
                "source": row["source"],
                "title": row["title"],
                "trust": row["trust"],
                "tags": [],
            }
            order.append(rid)
        if row["tag"] is not None:
            refs[rid]["tags"].append(row["tag"])
    return [refs[rid] for rid in order]


def run() -> None:
    """Console-script entry point: init DB then serve over stdio."""
    # Eager init: surfaces config / migration errors before MCP handshake,
    # and runs FTS5 backfill so the first ``search_cves_text`` isn't slow.
    try:
        _get_store()
    except Exception as exc:
        logger.error("vulnify-mcp startup failed: {}", exc)
        raise
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
