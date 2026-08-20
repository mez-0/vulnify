"""SQLite schema migrations for existing databases (additive-only)."""

from __future__ import annotations

import sqlite3
import time

from loguru import logger


def _table_exists(cur: sqlite3.Cursor, name: str) -> bool:
    cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (name,),
    )
    return cur.fetchone() is not None


def _index_exists(cur: sqlite3.Cursor, name: str) -> bool:
    cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name=? LIMIT 1",
        (name,),
    )
    return cur.fetchone() is not None


def _column_exists(cur: sqlite3.Cursor, table: str, column: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any(str(row[1]) == column for row in cur.fetchall())


def _add_column(
    conn: sqlite3.Connection, table: str, column: str, decl: str
) -> None:
    cur = conn.cursor()
    if not _table_exists(cur, table):
        return
    if _column_exists(cur, table, column):
        return
    cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _dedupe_affected_product(conn: sqlite3.Connection) -> None:
    """
    Collapse duplicate ``affected_product`` rows produced before
    ``affected_product_unique`` was enforced. Keeps the lowest ``id`` per
    ``(cve_id, product_id)`` group.

    On a backlog of ~500k rows the naïve ``DELETE … NOT IN (SELECT MIN(id)…
    GROUP BY)`` plan is correlated and runs for tens of minutes because each
    deleted row also fires the ``ON DELETE CASCADE`` to ``version_range``.
    Materialise the dup-id list into an indexed temp table, drop the cascade
    for the bulk delete, then sweep ``version_range`` orphans manually.
    """
    cur = conn.cursor()
    if not _table_exists(cur, "affected_product"):
        return

    cur.execute("DROP TABLE IF EXISTS _ap_dup_ids")
    cur.execute(
        """
        CREATE TEMPORARY TABLE _ap_dup_ids AS
        SELECT id FROM affected_product
        WHERE id NOT IN (
            SELECT MIN(id) FROM affected_product GROUP BY cve_id, product_id
        )
        """
    )
    cur.execute("CREATE INDEX _ap_dup_ids_idx ON _ap_dup_ids (id)")
    cur.execute("SELECT COUNT(*) FROM _ap_dup_ids")
    if int(cur.fetchone()[0]) == 0:
        cur.execute("DROP TABLE _ap_dup_ids")
        return

    fk_was_on = bool(cur.execute("PRAGMA foreign_keys").fetchone()[0])
    if fk_was_on:
        # FK enforcement state can only flip outside an active transaction.
        conn.commit()
        cur.execute("PRAGMA foreign_keys = OFF")
    try:
        cur.execute(
            "DELETE FROM affected_product WHERE id IN (SELECT id FROM _ap_dup_ids)"
        )
        cur.execute(
            "DELETE FROM version_range WHERE affected_product_id IN "
            "(SELECT id FROM _ap_dup_ids)"
        )
    finally:
        cur.execute("DROP TABLE _ap_dup_ids")
        if fk_was_on:
            conn.commit()
            cur.execute("PRAGMA foreign_keys = ON")


def _reassign_case_insensitive_product_refs(conn: sqlite3.Connection) -> None:
    """
    For ``product`` rows that differ only in case, point
    ``affected_product.product_id`` at the keeper (lowest ``product_id``).

    This may produce duplicates in ``affected_product`` — those get cleaned up
    by :func:`_dedupe_affected_product`, which must run *after* this step.
    """
    cur = conn.cursor()
    if not _table_exists(cur, "product"):
        return

    cur.execute(
        """
        SELECT vendor_id,
               lower(trim(name)) AS k_name,
               lower(trim(COALESCE(component, ''))) AS k_component,
               GROUP_CONCAT(product_id) AS ids,
               MIN(product_id) AS keeper
        FROM product
        GROUP BY vendor_id, k_name, k_component
        HAVING COUNT(*) > 1
        """
    )
    groups = cur.fetchall()
    for row in groups:
        keeper = int(row["keeper"])
        ids = [int(x) for x in str(row["ids"]).split(",")]
        losers = [pid for pid in ids if pid != keeper]
        if not losers:
            continue
        placeholders = ",".join("?" * len(losers))
        cur.execute(
            f"UPDATE affected_product SET product_id = ? "
            f"WHERE product_id IN ({placeholders})",
            (keeper, *losers),
        )
        cur.execute(
            f"DELETE FROM product WHERE product_id IN ({placeholders})",
            tuple(losers),
        )


def _dedupe_cpe_match(conn: sqlite3.Connection) -> None:
    """
    Collapse duplicate ``cpe_match`` rows produced before
    ``cpe_match_unique`` was enforced. Keeps the lowest ``id`` per
    ``(cve_id, criteria, COALESCE(match_criteria_id, ''))`` group.

    NVD lists the same CPE under multiple ``configurations[].nodes`` (one per
    AND-clause), and the original merger stamped one row per occurrence. The
    dup pattern is identical-row (same vulnerable flag), so drop is safe.
    """
    cur = conn.cursor()
    if not _table_exists(cur, "cpe_match"):
        return
    cur.execute(
        """
        DELETE FROM cpe_match
        WHERE id NOT IN (
            SELECT MIN(id) FROM cpe_match
            GROUP BY cve_id, criteria, COALESCE(match_criteria_id, '')
        )
        """
    )


def _column_is_not_null(cur: sqlite3.Cursor, table: str, column: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    for row in cur.fetchall():
        if str(row[1]) == column:
            return bool(row[3])  # row[3] == notnull
    return False


def _make_exploit_signals_nullable(conn: sqlite3.Connection) -> None:
    """
    Rebuild ``exploit`` so ``public_poc``/``metasploit`` are nullable tri-state.

    Older release DBs declared these ``INTEGER NOT NULL DEFAULT 0``, so every
    row reads ``public_poc = 0`` — which an agent (rightly) interprets as "no
    public PoC exists". But no provider ever *assessed* these signals; the 0 is
    a default, not a finding. SQLite can't drop a NOT NULL constraint in place,
    so rebuild the table, and null the legacy values (all of which are
    unassessed defaults) to recover the honest "not assessed" state.
    """
    cur = conn.cursor()
    if not _table_exists(cur, "exploit"):
        return
    if not _column_is_not_null(cur, "exploit", "public_poc"):
        return  # already migrated (or created fresh from the new schema)

    fk_was_on = bool(cur.execute("PRAGMA foreign_keys").fetchone()[0])
    if fk_was_on:
        # FK enforcement state can only flip outside an active transaction.
        conn.commit()
        cur.execute("PRAGMA foreign_keys = OFF")
    try:
        cur.execute("DROP TABLE IF EXISTS exploit_new")
        cur.execute(
            """
            CREATE TABLE exploit_new (
                cve_id TEXT PRIMARY KEY,
                maturity TEXT,
                public_poc INTEGER,
                metasploit INTEGER,
                ransomware_usage INTEGER NOT NULL DEFAULT 0,
                in_the_wild INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
            )
            """
        )
        cur.execute(
            """
            INSERT INTO exploit_new (
                cve_id, maturity, public_poc, metasploit,
                ransomware_usage, in_the_wild, notes
            )
            SELECT cve_id, maturity, NULL, NULL,
                   ransomware_usage, in_the_wild, notes
            FROM exploit
            """
        )
        cur.execute("DROP TABLE exploit")
        cur.execute("ALTER TABLE exploit_new RENAME TO exploit")
    finally:
        if fk_was_on:
            conn.commit()
            cur.execute("PRAGMA foreign_keys = ON")


def _drop_orphan_empty_vendor(conn: sqlite3.Connection) -> None:
    """
    Remove vendor rows with empty names that no longer have any product or
    ``cve_vendor`` edge — leftover sentinels from older ingest runs.
    """
    cur = conn.cursor()
    if not _table_exists(cur, "vendor"):
        return
    cur.execute(
        """
        DELETE FROM vendor
        WHERE trim(COALESCE(name, '')) = ''
          AND NOT EXISTS (SELECT 1 FROM cve_vendor WHERE vendor_id = vendor.vendor_id)
          AND NOT EXISTS (SELECT 1 FROM product WHERE vendor_id = vendor.vendor_id)
        """
    )


def apply_sqlite_migrations(conn: sqlite3.Connection) -> None:
    """
    Apply additive migrations after ``CREATE TABLE IF NOT EXISTS`` bootstrap.

    Safe to call on every open; no-ops when columns already exist.
    """
    cur = conn.cursor()
    if not _table_exists(cur, "cpe_match"):
        cur.execute(
            """
            CREATE TABLE cpe_match (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                criteria TEXT NOT NULL,
                match_criteria_id TEXT,
                vulnerable INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_cpe_match_cve ON cpe_match (cve_id)"
        )

    if not _table_exists(cur, "pipeline_run"):
        cur.execute(
            """
            CREATE TABLE pipeline_run (
                phase TEXT PRIMARY KEY,
                last_completed_at TEXT NOT NULL,
                last_watermark TEXT
            )
            """
        )

    if not _table_exists(cur, "exploit_artefact"):
        cur.execute(
            """
            CREATE TABLE exploit_artefact (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                source TEXT NOT NULL,
                stable_id TEXT,
                url TEXT,
                artefact_type TEXT,
                platform TEXT,
                published_date TEXT,
                confidence TEXT NOT NULL,
                FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
            )
            """
        )
    if not _index_exists(cur, "exploit_artefact_unique"):
        cur.execute(
            "CREATE UNIQUE INDEX exploit_artefact_unique "
            "ON exploit_artefact (cve_id, source, stable_id)"
        )

    _add_column(conn, "cve", "vuln_status", "TEXT")
    _add_column(conn, "cve", "source_identifier", "TEXT")

    _add_column(conn, "cvss", "metric_source", "TEXT")
    _add_column(conn, "cvss", "metric_type", "TEXT")
    _add_column(conn, "cvss", "exploitability_score", "REAL")
    _add_column(conn, "cvss", "impact_score", "REAL")

    _add_column(conn, "kev", "vulnerability_name", "TEXT")
    _add_column(conn, "kev", "required_action", "TEXT")
    _add_column(conn, "kev", "vendor_project", "TEXT")
    _add_column(conn, "kev", "product_label", "TEXT")
    _add_column(conn, "kev", "short_description", "TEXT")
    _add_column(conn, "kev", "source", "TEXT")

    has_ap_unique = _index_exists(cur, "affected_product_unique")
    has_product_unique = _index_exists(cur, "product_normalized_unique")

    if not has_product_unique:
        # Reassigning product_id under the AP UNIQUE index throws on every
        # collision before we even get a chance to dedup. Drop and re-create.
        if has_ap_unique:
            cur.execute("DROP INDEX affected_product_unique")
        _reassign_case_insensitive_product_refs(conn)
        _dedupe_affected_product(conn)
        cur.execute(
            "CREATE UNIQUE INDEX affected_product_unique "
            "ON affected_product (cve_id, product_id)"
        )
        cur.execute(
            "CREATE UNIQUE INDEX product_normalized_unique ON product ("
            "vendor_id, lower(trim(name)), lower(trim(COALESCE(component, '')))"
            ")"
        )
    elif not has_ap_unique:
        _dedupe_affected_product(conn)
        cur.execute(
            "CREATE UNIQUE INDEX affected_product_unique "
            "ON affected_product (cve_id, product_id)"
        )

    _drop_orphan_empty_vendor(conn)

    _make_exploit_signals_nullable(conn)

    if not _index_exists(cur, "cpe_match_unique"):
        _dedupe_cpe_match(conn)
        cur.execute(
            "CREATE UNIQUE INDEX cpe_match_unique ON cpe_match "
            "(cve_id, criteria, COALESCE(match_criteria_id, ''))"
        )

    # Backfill missing indexes that turn O(n) lookups into O(log n) — required
    # for the audit queries and the FK cascade on affected_product deletes.
    if not _index_exists(cur, "idx_reference_cve"):
        cur.execute("CREATE INDEX idx_reference_cve ON reference (cve_id)")
    if not _index_exists(cur, "idx_version_range_ap"):
        cur.execute(
            "CREATE INDEX idx_version_range_ap ON version_range (affected_product_id)"
        )
    # Product-id-leading counterpart to idx_affected_product_cve; the vendor
    # filter resolves a product set and needs to walk it back to CVEs.
    if not _index_exists(cur, "idx_affected_product_product"):
        cur.execute(
            "CREATE INDEX idx_affected_product_product "
            "ON affected_product (product_id, cve_id)"
        )
    # cve_vendor's PK leads with cve_id, leaving per-vendor CVE counts to scan
    # the whole table once per vendor.
    if not _index_exists(cur, "idx_cve_vendor_vendor"):
        cur.execute(
            "CREATE INDEX idx_cve_vendor_vendor ON cve_vendor (vendor_id, cve_id)"
        )

    _ensure_product_cpe_vendor(conn)

    _ensure_fts5_index(conn)


def _ensure_product_cpe_vendor(conn: sqlite3.Connection) -> None:
    """
    Create ``product_cpe_vendor`` and populate it from the CPE strings already
    in the DB, so vendor lookups work against a shipped release database.

    Derived purely from ``affected_product`` ⋈ ``cpe_match`` — no network — which
    is what makes it safe to run here rather than only in the pipeline. Without
    it, the ~11% of products owned by the empty sentinel vendor are unreachable
    by any vendor-name filter (see :mod:`vulnify.db.vendor_index`).

    Runs at most once per DB: guarded on the table being absent or empty, the
    same shape as :func:`_ensure_fts5_index`. The pipeline's ``vendor_index``
    phase keeps it fresh after that.
    """
    from vulnify.db.vendor_index import build_vendor_index

    cur = conn.cursor()
    fresh = not _table_exists(cur, "product_cpe_vendor")
    if fresh:
        cur.execute(
            """
            CREATE TABLE product_cpe_vendor (
                product_id INTEGER NOT NULL,
                slug TEXT NOT NULL,
                n INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (product_id, slug),
                FOREIGN KEY (product_id) REFERENCES product (product_id)
                    ON DELETE CASCADE
            )
            """
        )
    if not _index_exists(cur, "idx_product_cpe_vendor_slug"):
        cur.execute(
            "CREATE INDEX idx_product_cpe_vendor_slug ON product_cpe_vendor (slug)"
        )

    if not _table_exists(cur, "cpe_match"):
        return
    cur.execute("SELECT COUNT(*) FROM product_cpe_vendor")
    if int(cur.fetchone()[0]) > 0:
        return
    cur.execute("SELECT 1 FROM cpe_match LIMIT 1")
    if cur.fetchone() is None:
        return

    started = time.monotonic()
    logger.info("Building product/CPE-vendor index (one-off)...")
    build_vendor_index(conn)
    conn.commit()
    logger.info(
        "Product/CPE-vendor index built in {elapsed:.1f}s",
        elapsed=time.monotonic() - started,
    )


def _ensure_fts5_index(conn: sqlite3.Connection) -> None:
    """
    Create the ``cve_fts`` FTS5 virtual table + sync triggers, and backfill
    from ``cve`` on first run (older release DBs ship without it).
    """
    cur = conn.cursor()

    cur.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
            cve_id UNINDEXED,
            title,
            summary,
            technical_details,
            content='cve',
            content_rowid='rowid',
            tokenize='porter unicode61'
        )
        """
    )
    cur.execute(
        """
        CREATE TRIGGER IF NOT EXISTS cve_fts_ai AFTER INSERT ON cve BEGIN
            INSERT INTO cve_fts(rowid, cve_id, title, summary, technical_details)
            VALUES (new.rowid, new.cve_id, new.title, new.summary, new.technical_details);
        END
        """
    )
    cur.execute(
        """
        CREATE TRIGGER IF NOT EXISTS cve_fts_ad AFTER DELETE ON cve BEGIN
            INSERT INTO cve_fts(cve_fts, rowid, cve_id, title, summary, technical_details)
            VALUES ('delete', old.rowid, old.cve_id, old.title, old.summary, old.technical_details);
        END
        """
    )
    cur.execute(
        """
        CREATE TRIGGER IF NOT EXISTS cve_fts_au AFTER UPDATE ON cve BEGIN
            INSERT INTO cve_fts(cve_fts, rowid, cve_id, title, summary, technical_details)
            VALUES ('delete', old.rowid, old.cve_id, old.title, old.summary, old.technical_details);
            INSERT INTO cve_fts(rowid, cve_id, title, summary, technical_details)
            VALUES (new.rowid, new.cve_id, new.title, new.summary, new.technical_details);
        END
        """
    )

    # External-content FTS5 reports COUNT(*) from the underlying ``cve`` table
    # whether the index is built or not. The real signal is the internal
    # ``cve_fts_idx`` shadow table — empty when the index hasn't been built.
    cur.execute("SELECT COUNT(*) FROM cve_fts_idx")
    idx_built = int(cur.fetchone()[0]) > 0
    cur.execute("SELECT COUNT(*) FROM cve")
    cve_rows = int(cur.fetchone()[0])

    if not idx_built and cve_rows > 0:
        logger.info(
            "Backfilling FTS5 index over {} CVE rows — one-off, takes ~30s",
            cve_rows,
        )
        started = time.monotonic()
        cur.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')")
        conn.commit()
        logger.info(
            "FTS5 backfill complete in {:.1f}s", time.monotonic() - started
        )


__all__ = ["apply_sqlite_migrations"]
