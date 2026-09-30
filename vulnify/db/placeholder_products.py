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

import sqlite3
from collections import defaultdict

from loguru import logger

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

#: A CVE must name exactly one product slug for it to be repointed.
#:
#: 🚨 **Under-claim rather than guess.** A CVE listing several products is
#: usually a multi-product advisory, and picking the most frequent slug would
#: attach the whole CVE to one of them and hide it from searches for the others.
#: Leaving it on the placeholder keeps it *equally* unreachable, which is worse
#: for nobody and wrong for no one. Same discipline as the exploit tri-state:
#: the failure mode of an adjudicator must be "I do not know".
_MAX_DISTINCT_PRODUCTS = 1


def _parse_cpe(criteria: str) -> tuple[str, str] | None:
    """Pull ``(vendor, product)`` out of a CPE 2.3 URI.

    ``cpe:2.3:<part>:<vendor>:<product>:<version>:…`` — fixed positions, so a
    split is enough and no regex is warranted.

    :param criteria: The ``cpe_match.criteria`` value.
    :returns: Lowercased ``(vendor, product)``, or ``None`` when either
        component is absent or degenerate.
    """
    parts = criteria.split(":")
    if len(parts) < 5 or not criteria.startswith("cpe:2.3:"):
        return None
    vendor, product = parts[3].strip().lower(), parts[4].strip().lower()
    if vendor in _DEGENERATE_SLUGS or product in _DEGENERATE_SLUGS:
        return None
    return vendor, product


def _placeholder_product_ids(cur: sqlite3.Cursor) -> list[int]:
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


def _ensure_vendor(cur: sqlite3.Cursor, name: str) -> int:
    cur.execute("SELECT vendor_id FROM vendor WHERE lower(trim(name)) = ?", (name,))
    if (row := cur.fetchone()) is not None:
        return row[0]
    cur.execute("INSERT INTO vendor (name) VALUES (?)", (name,))
    return int(cur.lastrowid)


def _ensure_product(cur: sqlite3.Cursor, vendor_id: int, name: str) -> int:
    cur.execute(
        "SELECT product_id FROM product WHERE vendor_id = ? AND lower(trim(name)) = ?",
        (vendor_id, name),
    )
    if (row := cur.fetchone()) is not None:
        return row[0]
    cur.execute("INSERT INTO product (name, vendor_id) VALUES (?, ?)", (name, vendor_id))
    return int(cur.lastrowid)


def resolve_placeholder_products(conn: sqlite3.Connection) -> tuple[int, int]:
    """Repoint placeholder-product rows onto identities derived from CPE.

    Idempotent: a second run finds no placeholder-owned rows left to move for
    the CVEs it already resolved, and re-derives the same identity for any it
    could not.

    :param conn: Open connection to the corpus.
    :returns: ``(rows_repointed, cves_resolved)``.
    """
    cur = conn.cursor()
    placeholders = _placeholder_product_ids(cur)
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
          AND cm.criteria LIKE 'cpe:2.3:_:%'
        """,
        placeholders,
    )

    # cve_id -> the distinct (vendor, product) pairs its CPEs name.
    per_cve: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for cve_id, criteria in cur.fetchall():
        if (pair := _parse_cpe(criteria)) is not None:
            per_cve[cve_id].add(pair)

    resolved = {
        cve_id: next(iter(pairs))
        for cve_id, pairs in per_cve.items()
        if len(pairs) == _MAX_DISTINCT_PRODUCTS
    }
    if not resolved:
        logger.info("placeholder products: nothing unambiguous to resolve")
        return 0, 0

    product_ids: dict[tuple[str, str], int] = {}
    moved = 0
    for cve_id, pair in resolved.items():
        if (target := product_ids.get(pair)) is None:
            vendor, product = pair
            target = _ensure_product(cur, _ensure_vendor(cur, vendor), product)
            product_ids[pair] = target
        cur.execute(
            f"UPDATE affected_product SET product_id = ? "
            f"WHERE cve_id = ? AND product_id IN ({marks})",
            (target, cve_id, *placeholders),
        )
        moved += cur.rowcount

    logger.info(
        "placeholder products: repointed {} rows across {} CVEs onto {} identities "
        "({} left ambiguous)",
        moved, len(resolved), len(product_ids), len(per_cve) - len(resolved),
    )
    return moved, len(resolved)


__all__ = [
    "PLACEHOLDER_PRODUCT_NAMES",
    "resolve_placeholder_products",
]
