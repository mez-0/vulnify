"""Recover product identity for CVEs whose CNA wrote a placeholder.

**The defect.** ``providers/cveproject.py`` filters placeholder *vendor* strings
(``n/a`` / ``unknown`` / ``none``) and substitutes the sentinel vendor. It applies
no equivalent filter to the *product*, which is written verbatim — so a CNA
record carrying ``"product": "n/a"`` creates a product literally named ``n/a``.
That one row is shared by every such CVE, and no ``product.name LIKE '%x%'``
query can ever reach any of them. It is the single largest blind spot in
product-based lookup.

**Why it is recoverable without re-fetching.** NVD's CPE 2.3 strings in
``cpe_match`` carry both a vendor and a **product** component, and the ingest
already stores them. Measured on the shipped corpus: of the CVEs sitting on the
placeholder product, ~98% have at least one ``cpe_match`` row with a parseable,
non-degenerate product slug.

🚨 **This cannot reuse** :mod:`vulnify.db.vendor_index`. That module rolls CPE
evidence up **per ``product_id``**, and every placeholder CVE shares one
``product_id`` — which accumulates tens of thousands of distinct slugs and is
excluded by ``MAX_SLUGS_PER_PRODUCT`` precisely so a search for one vendor does
not match all of them. The guard is right; the granularity is wrong for this
question. Identity here is a fact about **a CVE**, so the join is
``affected_product`` ⋈ ``cpe_match`` on ``cve_id`` and never a product roll-up.

⚠️ **Do NOT "fix" this by refusing the placeholder at ingest.** The symmetric
change — filtering the product the way ``_truthy_vendor`` filters the vendor —
looks like the obvious repair and breaks this module: with no
``affected_product`` row there is nothing to join ``cpe_match`` against, and the
CVE becomes unreachable by product *and* invisible to the repair. The
placeholder row is the anchor. (Ingest cannot resolve identity itself either:
cvelistV5 records carry no CPEs, and ``cpe_match`` is populated by the later NVD
phase. Measured: only 226 CVEs in the corpus have a ``cpe_match`` row and no
``affected_product`` row, so the anchor is present essentially everywhere.)

⚠️ **A migration alone would be silently undone.** Ingestion is a full re-parse
of the bulk archive and ``ensure_product`` keys on the exact normalised name, so
the next gather reinserts the placeholder straight from the source JSON. This
runs as a phase on **every** gather, after the NVD phase that populates
``cpe_match``, for the same reason ``vendor_index`` does.
"""

from __future__ import annotations

import re
import sqlite3
from collections import defaultdict

from loguru import logger

from vulnify.constants import AFFECTED_SOURCE_CPE

#: Product strings a CNA writes when it declines to name one. Matched
#: case-insensitively after stripping. Mirrors ``_truthy_vendor``'s set in
#: ``providers/cveproject.py`` — the asymmetry between the two is the bug this
#: module exists to repair, so they are deliberately the same words.
PLACEHOLDER_PRODUCT_NAMES: frozenset[str] = frozenset({
    "n/a", "n\\a", "na", "unknown", "none", "not applicable", "-", "",
})

#: CPE components carrying no information. ``*`` and ``-`` are the CPE 2.3
#: wildcard and NA markers; the rest are placeholders by another name.
_DEGENERATE_SLUGS: frozenset[str] = frozenset({"", "*", "-", "n/a", "n\\a", "other"})

#: 🚨 **Every vulnerable pair, never the most frequent one.** A CVE whose CPEs
#: name several products is usually a multi-product advisory. Picking one slug
#: would attach the whole CVE to it and hide it from searches for the others;
#: that is the guess this module refuses to make. The earlier rule — resolve
#: only CVEs naming *exactly one* pair — avoided the guess by resolving nothing,
#: which left 40,643 CVEs (2026-11-02 build) unreachable by vendor *and*
#: product. Writing one ``affected_product`` row per pair hides nothing and
#: claims only what NVD's configuration states.
#:
#: ⚠️ **Only ``vulnerable = 1`` rows.** NVD configurations carry platform CPEs
#: with ``vulnerable = false`` — the Windows an application runs on, the
#: hardware model beside its ``_firmware``. Fanning those out would attach a
#: third-party app CVE to Microsoft. 594k of the 3.2M ``cpe_match`` rows are
#: non-vulnerable.


#: A CPE 2.3 component separator: a colon not escaped by a backslash.
_CPE_SPLIT = re.compile(r"(?<!\\):")

#: CPE 2.3 quoting — ``\+``, ``\&``, ``\:`` and friends stand for the bare
#: character. Left in, ``ftp\+\+_server`` never matches a search for ``ftp++``.
_CPE_UNQUOTE = re.compile(r"\\(.)")


def _parse_cpe(criteria: str) -> tuple[str, str] | None:
    """Pull ``(vendor, product)`` out of a CPE 2.3 URI.

    ``cpe:2.3:<part>:<vendor>:<product>:<version>:…`` — fixed positions, but a
    component may contain an escaped ``\\:``, so the split honours escapes and
    the components are unquoted afterwards.

    :param criteria: The ``cpe_match.criteria`` value.
    :returns: Lowercased, unquoted ``(vendor, product)``, or ``None`` when
        either component is absent or degenerate.
    """
    if not criteria.startswith("cpe:2.3:"):
        return None
    parts = _CPE_SPLIT.split(criteria)
    if len(parts) < 5:
        return None
    vendor, product = (
        _CPE_UNQUOTE.sub(r"\1", c).strip().lower() for c in (parts[3], parts[4])
    )
    if vendor in _DEGENERATE_SLUGS or product in _DEGENERATE_SLUGS:
        return None
    return vendor, product


def _humanise(slug: str) -> str:
    """``palo_alto_networks`` → ``palo alto networks``.

    CPE uses ``_`` for a space. Stored verbatim, the slug is unreachable by the
    phrase a person actually types — ``LIKE '%internet explorer%'`` does not
    match ``internet_explorer``.
    """
    return " ".join(slug.replace("_", " ").split())


def _norm_key(name: str) -> str:
    """Punctuation- and case-blind key: ``Hitachi Vantara`` ≡ ``hitachivantara``."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def placeholder_product_ids(cur: sqlite3.Cursor) -> list[int]:
    """Product rows whose name is a CNA placeholder.

    Usually one shared row, but the query does not assume that: a real vendor
    that wrote ``n/a`` in the product field produces its own row under its own
    ``vendor_id``, and those are the same defect at a smaller scale.
    """
    cur.execute("SELECT product_id, name FROM product")
    return [
        pid for pid, name in cur.fetchall()
        if (name or "").strip().lower() in PLACEHOLDER_PRODUCT_NAMES
    ]


class _IdentityResolver:
    """Map a CPE ``(vendor, product)`` onto an existing row, else create one.

    🚨 **Prefer the row that already exists.** A CPE slug is a second spelling
    of a name cvelistV5 usually already has — ``hitachivantara`` for ``Hitachi
    Vantara``. Minting a fresh vendor per slug would split one vendor in two,
    and a search for the name people type would find only the half that was
    already there. A punctuation-blind key catches the respelling; it is used
    only when it names exactly **one** row, because a key shared by two rows
    (``arisoft`` / ``ARI Soft``) is a coin toss, and the humanised spelling is
    created or matched exactly instead.
    """

    def __init__(self, cur: sqlite3.Cursor) -> None:
        self._cur = cur
        self._vendors: dict[str, list[int]] = defaultdict(list)
        cur.execute("SELECT vendor_id, name FROM vendor WHERE trim(name) <> ''")
        for vid, name in cur.fetchall():
            self._vendors[_norm_key(name)].append(vid)
        self._products: dict[int, dict[str, list[int]]] = {}
        self._cache: dict[tuple[str, str], int] = {}

    def product_id(self, vendor_slug: str, product_slug: str) -> int:
        key = (vendor_slug, product_slug)
        if (hit := self._cache.get(key)) is None:
            vendor_id = self._vendor_id(vendor_slug)
            hit = self._cache[key] = self._product_id(vendor_id, product_slug)
        return hit

    def created_count(self) -> int:
        return len(self._cache)

    def _vendor_id(self, slug: str) -> int:
        if len(ids := self._vendors.get(_norm_key(slug), [])) == 1:
            return ids[0]
        name = _humanise(slug)
        self._cur.execute(
            "SELECT vendor_id FROM vendor WHERE lower(trim(name)) = ?", (name,))
        if (row := self._cur.fetchone()) is not None:
            return row[0]
        self._cur.execute("INSERT INTO vendor (name) VALUES (?)", (name,))
        vid = int(self._cur.lastrowid)
        self._vendors[_norm_key(name)].append(vid)
        return vid

    def _product_id(self, vendor_id: int, slug: str) -> int:
        if (by_key := self._products.get(vendor_id)) is None:
            by_key = self._products[vendor_id] = defaultdict(list)
            self._cur.execute(
                "SELECT product_id, name FROM product WHERE vendor_id = ?", (vendor_id,))
            for pid, name in self._cur.fetchall():
                if (name or "").strip().lower() not in PLACEHOLDER_PRODUCT_NAMES:
                    by_key[_norm_key(name)].append(pid)
        if len(ids := by_key.get(_norm_key(slug), [])) == 1:
            return ids[0]
        name = _humanise(slug)
        self._cur.execute(
            "SELECT product_id FROM product WHERE vendor_id = ? AND lower(trim(name)) = ?",
            (vendor_id, name),
        )
        if (row := self._cur.fetchone()) is not None:
            return row[0]
        self._cur.execute(
            "INSERT INTO product (name, vendor_id) VALUES (?, ?)", (name, vendor_id))
        pid = int(self._cur.lastrowid)
        by_key[_norm_key(name)].append(pid)
        return pid


def resolve_placeholder_products(conn: sqlite3.Connection) -> tuple[int, int]:
    """Give placeholder-product CVEs every identity their vulnerable CPEs name.

    For each CVE still anchored on a placeholder product: the anchor row is
    repointed onto the first ``(vendor, product)`` pair (keeping its
    ``version_range`` rows), a further ``affected_product`` row is written for
    each remaining pair, every row this writes is stamped
    ``source = 'cpe'``, and each pair's vendor gets the ``affected``
    ``cve_vendor`` edge the cvelistV5 upsert would have written had the CNA
    named it.

    Idempotent: a second run finds no placeholder anchor left for the CVEs it
    resolved, and re-derives the same rows for any whose anchor could not move.

    :param conn: Open connection to the corpus.
    :returns: ``(rows_written, cves_resolved)`` — repointed anchors plus new rows.
    """
    cur = conn.cursor()
    placeholders = placeholder_product_ids(cur)
    if not placeholders:
        logger.info("placeholder products: none present")
        return 0, 0

    marks = ",".join("?" * len(placeholders))
    cur.execute(
        f"""
        SELECT ap.cve_id, cm.criteria
        FROM affected_product ap
        JOIN cpe_match cm ON cm.cve_id = ap.cve_id
        WHERE ap.product_id IN ({marks})
          AND cm.vulnerable = 1
          AND cm.criteria LIKE 'cpe:2.3:_:%'
        """,
        placeholders,
    )

    # cve_id -> the distinct (vendor, product) pairs its vulnerable CPEs name.
    per_cve: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for cve_id, criteria in cur.fetchall():
        if (pair := _parse_cpe(criteria)) is not None:
            per_cve[cve_id].add(pair)
    if not per_cve:
        logger.info("placeholder products: no CPE evidence to resolve from")
        return 0, 0

    identities = _IdentityResolver(cur)
    repointed = inserted = 0
    for cve_id, pairs in per_cve.items():
        # Sorted so the anchor's destination is stable across gathers.
        targets = list(dict.fromkeys(identities.product_id(v, p) for v, p in sorted(pairs)))
        repointed += _repoint_anchor(cur, cve_id, targets, placeholders)
        inserted += _write_fanout(cur, cve_id, targets)
        _write_vendor_edges(cur, cve_id, targets)

    logger.info(
        "placeholder products: {} CVEs resolved — {} anchors repointed, {} rows "
        "added, {} distinct identities",
        len(per_cve), repointed, inserted, identities.created_count(),
    )
    return repointed + inserted, len(per_cve)


def _repoint_anchor(
    cur: sqlite3.Cursor, cve_id: str, targets: list[int], placeholders: list[int]
) -> int:
    """Move the placeholder row onto the first target the CVE does not already hold.

    🚨 ``affected_product_unique`` is ``(cve_id, product_id)``, and a CVE may
    already carry a real row on a resolved product; repointing onto that one
    raises and aborts the gather. Trying the targets in turn keeps the anchor's
    ``version_range`` rows on a real product whenever any target is free; when
    none is, the anchor stays and the CVE is reachable through the others.
    """
    marks = ",".join("?" * len(placeholders))
    for target in targets:
        if _holds(cur, cve_id, target):
            continue
        cur.execute(
            f"UPDATE affected_product SET product_id = ?, source = ? "
            f"WHERE id = (SELECT id FROM affected_product "
            f"            WHERE cve_id = ? AND product_id IN ({marks}) ORDER BY id LIMIT 1)",
            (target, AFFECTED_SOURCE_CPE, cve_id, *placeholders),
        )
        return cur.rowcount
    return 0


def _write_fanout(cur: sqlite3.Cursor, cve_id: str, targets: list[int]) -> int:
    """One ``affected_product`` row per target the CVE does not already hold.

    Existence-checked rather than ``INSERT OR IGNORE``: ``schema.sql`` does not
    declare ``affected_product_unique`` (the migration adds it), so on a fresh
    bootstrap there is no constraint for ``OR IGNORE`` to lean on.
    """
    written = 0
    for target in targets:
        if _holds(cur, cve_id, target):
            continue
        cur.execute(
            "INSERT INTO affected_product (cve_id, product_id, affected, notes, source) "
            "VALUES (?, ?, 1, '', ?)",
            (cve_id, target, AFFECTED_SOURCE_CPE),
        )
        written += 1
    return written


def _write_vendor_edges(cur: sqlite3.Cursor, cve_id: str, targets: list[int]) -> None:
    """The ``affected`` vendor edge for each target's owning vendor.

    Mirrors ``AffectedVendorEdgesStep`` in the cvelistV5 upsert, so a consumer
    reading vendors through ``cve_vendor`` sees the same CVE a product join does.
    """
    marks = ",".join("?" * len(targets))
    cur.execute(
        f"""
        INSERT OR IGNORE INTO cve_vendor (cve_id, vendor_id, role)
        SELECT DISTINCT ?, p.vendor_id, 'affected' FROM product p
        WHERE p.product_id IN ({marks})
          AND p.vendor_id NOT IN (SELECT vendor_id FROM cve_vendor
                                  WHERE cve_id = ? AND role = 'primary')
        """,
        (cve_id, *targets, cve_id),
    )


def _holds(cur: sqlite3.Cursor, cve_id: str, product_id: int) -> bool:
    cur.execute(
        "SELECT 1 FROM affected_product WHERE cve_id = ? AND product_id = ? LIMIT 1",
        (cve_id, product_id),
    )
    return cur.fetchone() is not None


__all__ = [
    "PLACEHOLDER_PRODUCT_NAMES",
    "placeholder_product_ids",
    "resolve_placeholder_products",
]
