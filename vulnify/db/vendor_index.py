"""Derived vendor index: CPE vendor slugs per product, and sentinel repointing.

Two operations, both pure SQL over tables already in the DB (no network), so
they can run either as a pipeline phase or from
:func:`vulnify.db.migrate.apply_sqlite_migrations` against a shipped release DB.

**Why this exists.** ``providers/cveproject.py`` rejects cvelistV5 vendor strings
of ``n/a`` / ``unknown`` / ``none`` / ``""`` and substitutes a bare ``Vendor()``.
The *product* is still created, so ~11% of ``product`` rows end up owned by a
single empty-named sentinel vendor row, and ``lower(name) LIKE '%x%'`` can never
match ``''``. NVD's CPE 2.3 strings in ``cpe_match`` carry a vendor component
that nothing in the codebase parsed — that slug is the only structured vendor
signal those products have.
"""

from __future__ import annotations

import sqlite3

from loguru import logger

# A slug must own at least this share of a product's CPE evidence before we will
# repoint the product onto it. Below the bar we leave the product on the sentinel
# rather than guess — the same under-claim discipline the exploit tri-state uses.
#
# This is load-bearing. The ``n/a`` product (the cvelistV5 placeholder, and the
# single largest block of sentinel-owned rows) has a top-slug share of ~7%
# spread across linux/mozilla/apple; ``kernel`` sits at ~40%. Both must stay put.
DOMINANCE_THRESHOLD = 0.80

# A product row whose CPE evidence names more vendors than this is not a product,
# it is a placeholder or a meta-distribution, and its slugs carry no vendor
# signal. Excluding them is load-bearing, not tidying: the cvelistV5 ``n/a``
# placeholder product accumulates **26,354** distinct slugs (it is shared by
# ~143k CVEs), so without this guard it matches *every* vendor term and a search
# for ``aruba`` returns 144,237 CVEs instead of 576. ``Red Hat Enterprise Linux
# 8`` is the same shape at 95 slugs — one per packaged upstream.
#
# The real distribution is sharply bimodal, so the exact cut hardly matters:
# 46,280 products have 1-2 slugs and 48,249 have <= 8, against 216 above it.
MAX_SLUGS_PER_PRODUCT = 8

# Within a kept product, ignore slugs holding less than this share of its
# evidence. Kills strays — ``Aruba ClearPass Policy Manager`` carries
# ``arubanetworks`` x337 alongside a stray ``microsoft`` x2 and ``apple`` x1.
MIN_SLUG_SHARE = 0.05

# ...and an absolute floor, because a share is meaningless on thin evidence: a
# product seen twice, once beside an unrelated CPE, gives that stray a 50% share.
# This is what stops Dell's ``iDRAC Service Module`` (one lone ``citrix`` CPE
# occurrence) from answering a search for Citrix.
MIN_SLUG_EVIDENCE = 2

# ``cpe:2.3:<part>:<vendor>:…`` — the fixed prefix is 10 chars and CPE 2.3 pins
# ``part`` to a single character, so the vendor component always starts at 1-based
# offset 11 and runs to the next colon. Verified against 3,104,461 rows with zero
# rejects under the ``cpe:2.3:_:%`` guard. (A vendor containing an escaped ``\:``
# would truncate early; those land in the degenerate-slug filter below.)
_SLUG_EXPR = "substr(cm.criteria, 11, instr(substr(cm.criteria, 11), ':') - 1)"

# Wildcard / placeholder CPE components carry no vendor information.
_DEGENERATE_SLUGS = ("", "*", "-", "n\\/a", "other")


def _table_exists(cur: sqlite3.Cursor, name: str) -> bool:
    cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (name,),
    )
    return cur.fetchone() is not None


def rebuild_product_cpe_vendor(conn: sqlite3.Connection) -> int:
    """
    Rebuild ``product_cpe_vendor`` wholesale from ``affected_product`` ⋈ ``cpe_match``.

    Wholesale rather than incremental on purpose: ``affected_product`` and
    ``cpe_match`` are both cascade-wiped and rebuilt when a CVE is re-ingested,
    so any incremental bookkeeping would drift. A full rebuild is ~5s on the
    full corpus and is trivially idempotent.

    The caller owns the transaction — this does not commit.

    :param conn: An open SQLite connection.
    :type conn: sqlite3.Connection
    :return: Number of ``(product_id, slug)`` rows written.
    :rtype: int
    """
    cur = conn.cursor()
    for table in ("product_cpe_vendor", "affected_product", "cpe_match"):
        if not _table_exists(cur, table):
            return 0

    placeholders = ",".join("?" * len(_DEGENERATE_SLUGS))
    cur.execute("DELETE FROM product_cpe_vendor")
    cur.execute(
        f"""
        INSERT INTO product_cpe_vendor (product_id, slug, n)
        WITH tally AS (
            SELECT product_id, slug, COUNT(*) AS n
            FROM (
                SELECT ap.product_id AS product_id, {_SLUG_EXPR} AS slug
                FROM affected_product ap
                JOIN cpe_match cm ON cm.cve_id = ap.cve_id
                WHERE cm.criteria LIKE 'cpe:2.3:_:%'
            )
            WHERE slug NOT IN ({placeholders})
            GROUP BY product_id, slug
        ),
        kept AS (
            SELECT product_id, SUM(n) AS total
            FROM tally
            GROUP BY product_id
            HAVING COUNT(*) <= ?
        )
        SELECT t.product_id, t.slug, t.n
        FROM tally t
        JOIN kept k ON k.product_id = t.product_id
        WHERE t.n >= ? AND t.n * 1.0 / k.total >= ?
        """,
        (
            *_DEGENERATE_SLUGS,
            MAX_SLUGS_PER_PRODUCT,
            MIN_SLUG_EVIDENCE,
            MIN_SLUG_SHARE,
        ),
    )
    cur.execute("SELECT COUNT(*) FROM product_cpe_vendor")
    return int(cur.fetchone()[0])


def _sentinel_vendor_id(cur: sqlite3.Cursor) -> int | None:
    """The empty-named placeholder vendor, or ``None`` if the DB has none."""
    cur.execute("SELECT vendor_id FROM vendor WHERE trim(COALESCE(name, '')) = ''")
    row = cur.fetchone()
    return None if row is None else int(row[0])


def _vendor_ids_by_folded_name(cur: sqlite3.Cursor) -> dict[str, int]:
    """
    Map every real vendor name to its id under two foldings.

    CPE slugs are lowercase and underscore-separated (``red_hat``) while
    ``vendor.name`` is human-spelled (``Red Hat``), so both the raw fold and the
    underscores-to-spaces fold are indexed. Raw wins on collision.
    """
    cur.execute("SELECT vendor_id, name FROM vendor WHERE trim(COALESCE(name, '')) <> ''")
    spaced: dict[str, int] = {}
    exact: dict[str, int] = {}
    for vendor_id, name in cur.fetchall():
        folded = str(name).strip().lower()
        exact.setdefault(folded, int(vendor_id))
        spaced.setdefault(folded.replace(" ", "_"), int(vendor_id))
    return {**spaced, **exact}


def repoint_sentinel_products(conn: sqlite3.Connection) -> int:
    """
    Move sentinel-owned products onto the real vendor their CPE evidence names.

    Only acts when the evidence is unambiguous (a single slug, or one clearing
    :data:`DOMINANCE_THRESHOLD`) **and** the slug already matches an existing
    ``vendor`` row. Slugs with no matching vendor are left alone rather than
    minted as new vendors — CPE slugs like ``404like_project`` or ``wp-plugins``
    would pollute the vendor namespace and surface in the dashboard's
    top-vendors charts.

    Merges rather than reassigns. ``ensure_product`` keys on
    ``(vendor_id, name, component)``, so a bare ``UPDATE product SET vendor_id``
    would make the next gather's lookup miss and insert a *fresh* duplicate under
    the sentinel — one per gather, forever. Where the destination product already
    exists we repoint ``affected_product`` at it and drop the loser row instead.

    The caller owns the transaction — this does not commit.

    :param conn: An open SQLite connection.
    :type conn: sqlite3.Connection
    :return: Number of products repointed onto a real vendor.
    :rtype: int
    """
    cur = conn.cursor()
    for table in ("product_cpe_vendor", "product", "vendor", "affected_product"):
        if not _table_exists(cur, table):
            return 0

    sentinel = _sentinel_vendor_id(cur)
    if sentinel is None:
        return 0

    by_name = _vendor_ids_by_folded_name(cur)
    if not by_name:
        return 0

    # Winning slug per sentinel-owned product, with the totals needed to judge
    # dominance. One row per product; ties resolve to the lexically-first slug,
    # which is deterministic and irrelevant below the threshold anyway.
    cur.execute(
        """
        SELECT pcv.product_id,
               SUM(pcv.n) AS total,
               MAX(pcv.n) AS best,
               (SELECT p2.slug FROM product_cpe_vendor p2
                 WHERE p2.product_id = pcv.product_id
                 ORDER BY p2.n DESC, p2.slug ASC LIMIT 1) AS slug,
               COUNT(*) AS distinct_slugs
        FROM product_cpe_vendor pcv
        JOIN product p ON p.product_id = pcv.product_id
        WHERE p.vendor_id = ?
        GROUP BY pcv.product_id
        """,
        (sentinel,),
    )
    candidates = cur.fetchall()

    moved = 0
    for row in candidates:
        product_id = int(row["product_id"])
        total = int(row["total"] or 0)
        best = int(row["best"] or 0)
        slug = str(row["slug"] or "")
        if total <= 0 or not slug:
            continue
        if int(row["distinct_slugs"]) > 1 and (best / total) < DOMINANCE_THRESHOLD:
            continue  # ambiguous — under-claim, leave it on the sentinel
        target_vendor = by_name.get(slug)
        if target_vendor is None or target_vendor == sentinel:
            continue
        if _move_product(cur, product_id, target_vendor):
            moved += 1
    return moved


def _move_product(cur: sqlite3.Cursor, product_id: int, vendor_id: int) -> bool:
    """
    Move one product to ``vendor_id``, merging into an existing twin if present.

    :return: True when the product was moved or merged away.
    :rtype: bool
    """
    cur.execute(
        "SELECT name, COALESCE(component, '') AS component FROM product "
        "WHERE product_id = ?",
        (product_id,),
    )
    row = cur.fetchone()
    if row is None:
        return False
    name, component = str(row["name"]), str(row["component"])

    cur.execute(
        """
        SELECT product_id FROM product
        WHERE vendor_id = ?
          AND lower(trim(name)) = lower(trim(?))
          AND lower(trim(COALESCE(component, ''))) = lower(trim(?))
        """,
        (vendor_id, name, component),
    )
    twin = cur.fetchone()

    if twin is None:
        cur.execute(
            "UPDATE product SET vendor_id = ? WHERE product_id = ?",
            (vendor_id, product_id),
        )
        return True

    keeper = int(twin["product_id"])
    if keeper == product_id:
        return False

    # Drop rows that would collide with the keeper under
    # ``affected_product_unique (cve_id, product_id)``, then repoint the rest.
    # ``version_range`` cascades off the deleted ``affected_product`` rows.
    cur.execute(
        """
        DELETE FROM affected_product
        WHERE product_id = ?
          AND EXISTS (
              SELECT 1 FROM affected_product keep
              WHERE keep.cve_id = affected_product.cve_id
                AND keep.product_id = ?
          )
        """,
        (product_id, keeper),
    )
    cur.execute(
        "UPDATE affected_product SET product_id = ? WHERE product_id = ?",
        (keeper, product_id),
    )
    cur.execute("DELETE FROM product WHERE product_id = ?", (product_id,))
    return True


def build_vendor_index(conn: sqlite3.Connection) -> tuple[int, int]:
    """
    Full pass: build the slug index, repoint what it resolves, rebuild the index.

    The second rebuild is not redundant — repointing merges product rows away,
    and ``product_cpe_vendor`` is keyed by ``product_id``, so the keeper products
    need their evidence recomputed afterwards.

    The caller owns the transaction — this does not commit.

    :param conn: An open SQLite connection.
    :type conn: sqlite3.Connection
    :return: ``(slug_rows, products_repointed)``.
    :rtype: tuple[int, int]
    """
    rebuild_product_cpe_vendor(conn)
    moved = repoint_sentinel_products(conn)
    rows = rebuild_product_cpe_vendor(conn) if moved else _count_slugs(conn)
    logger.info(
        "vendor index: {rows:,} product/CPE-vendor rows, {moved:,} product(s) "
        "repointed off the placeholder vendor",
        rows=rows,
        moved=moved,
    )
    return rows, moved


def _count_slugs(conn: sqlite3.Connection) -> int:
    cur = conn.cursor()
    if not _table_exists(cur, "product_cpe_vendor"):
        return 0
    cur.execute("SELECT COUNT(*) FROM product_cpe_vendor")
    return int(cur.fetchone()[0])


__all__ = [
    "DOMINANCE_THRESHOLD",
    "MAX_SLUGS_PER_PRODUCT",
    "MIN_SLUG_EVIDENCE",
    "MIN_SLUG_SHARE",
    "build_vendor_index",
    "rebuild_product_cpe_vendor",
    "repoint_sentinel_products",
]
