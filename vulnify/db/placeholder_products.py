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

    identities = _IdentityResolver(cur)
    moved = 0
    for cve_id, (vendor, product) in resolved.items():
        target = identities.product_id(vendor, product)
        # 🚨 ``OR IGNORE``: ``affected_product_unique`` is (cve_id, product_id),
        # and a CVE may already carry a real row on the resolved product. A
        # plain UPDATE raises there and aborts the gather; the CVE is already
        # reachable through that row, so leaving the placeholder row is free.
        cur.execute(
            f"UPDATE OR IGNORE affected_product SET product_id = ? "
            f"WHERE cve_id = ? AND product_id IN ({marks})",
            (target, cve_id, *placeholders),
        )
        moved += cur.rowcount

    logger.info(
        "placeholder products: repointed {} rows across {} CVEs onto {} identities "
        "({} left ambiguous)",
        moved, len(resolved), identities.created_count(), len(per_cve) - len(resolved),
    )
    return moved, len(resolved)


__all__ = [
    "PLACEHOLDER_PRODUCT_NAMES",
    "resolve_placeholder_products",
]
