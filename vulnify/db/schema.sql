-- Normalized CVE graph. Enable foreign keys in application (PRAGMA foreign_keys = ON).

CREATE TABLE IF NOT EXISTS cve (
    cve_id TEXT PRIMARY KEY,
    title TEXT,
    cna TEXT,
    summary TEXT,
    technical_details TEXT,
    published TEXT,
    modified TEXT,
    discovered TEXT,
    priority_score INTEGER,
    confidence REAL,
    data_version TEXT,
    data_type TEXT,
    state TEXT,
    assigner_org_id TEXT,
    vuln_status TEXT,
    source_identifier TEXT
);

CREATE TABLE IF NOT EXISTS vendor (
    vendor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    website TEXT,
    country TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS vendor_name_normalized ON vendor (lower(trim(name)));

CREATE TABLE IF NOT EXISTS cve_vendor (
    cve_id TEXT NOT NULL,
    vendor_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (cve_id, vendor_id, role),
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE,
    FOREIGN KEY (vendor_id) REFERENCES vendor (vendor_id)
);

CREATE TABLE IF NOT EXISTS product (
    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    vendor_id INTEGER NOT NULL,
    product_type TEXT,
    family TEXT,
    component TEXT,
    FOREIGN KEY (vendor_id) REFERENCES vendor (vendor_id),
    UNIQUE (vendor_id, name, component)
);

CREATE INDEX IF NOT EXISTS idx_product_name ON product (name);

CREATE TABLE IF NOT EXISTS affected_product (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    product_id INTEGER NOT NULL,
    affected INTEGER NOT NULL DEFAULT 1,
    notes TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES product (product_id)
);

CREATE INDEX IF NOT EXISTS idx_affected_product_cve ON affected_product (cve_id, product_id);

CREATE TABLE IF NOT EXISTS version_range (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    affected_product_id INTEGER NOT NULL,
    start_including TEXT,
    start_excluding TEXT,
    end_including TEXT,
    end_excluding TEXT,
    fixed_version TEXT,
    raw_text TEXT,
    FOREIGN KEY (affected_product_id) REFERENCES affected_product (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_version_range_ap ON version_range (affected_product_id);

CREATE TABLE IF NOT EXISTS cwe (
    cwe_id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS cve_cwe (
    cve_id TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, cwe_id),
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE,
    FOREIGN KEY (cwe_id) REFERENCES cwe (cwe_id)
);

CREATE TABLE IF NOT EXISTS cvss (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    version TEXT,
    score REAL,
    vector TEXT,
    severity TEXT,
    attack_vector TEXT,
    attack_complexity TEXT,
    privileges_required TEXT,
    user_interaction TEXT,
    scope TEXT,
    confidentiality TEXT,
    integrity TEXT,
    availability TEXT,
    metric_source TEXT,
    metric_type TEXT,
    exploitability_score REAL,
    impact_score REAL,
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cvss_cve_score ON cvss (cve_id, score);

CREATE TABLE IF NOT EXISTS exploit (
    cve_id TEXT PRIMARY KEY,
    maturity TEXT,
    -- Tri-state: NULL = not assessed by any source (the current default — no
    -- PoC/Metasploit provider is wired yet), 0/1 once a source has looked.
    public_poc INTEGER,
    metasploit INTEGER,
    ransomware_usage INTEGER NOT NULL DEFAULT 0,
    in_the_wild INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
);

-- Per-CVE exploit evidence: many artefacts per CVE (Nuclei templates,
-- Exploit-DB entries, Metasploit modules) backing the ``exploit`` summary
-- bools above. Enrichment-owned — written outside the cvelistV5 upsert graph,
-- so the ``ON DELETE CASCADE`` means a CVE re-ingest wipes these rows and they
-- heal on the next exploit phase run (see docs/PIPELINE.md). ``confidence`` is
-- a provenance vocab (``exact``/``parsed``/``heuristic``), enforced in the
-- ingest layer rather than a CHECK constraint. The ``exploit_artefact_unique``
-- index ``(cve_id, source, stable_id)`` keeps re-ingest upserts idempotent and
-- also serves ``WHERE cve_id = ?`` lookups via its leftmost column.
CREATE TABLE IF NOT EXISTS exploit_artefact (
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
);

CREATE UNIQUE INDEX IF NOT EXISTS exploit_artefact_unique
    ON exploit_artefact (cve_id, source, stable_id);

CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY,
    listed INTEGER NOT NULL DEFAULT 0,
    date_added TEXT,
    due_date TEXT,
    notes TEXT,
    vulnerability_name TEXT,
    required_action TEXT,
    vendor_project TEXT,
    product_label TEXT,
    short_description TEXT,
    source TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_kev_listed ON kev (listed);

CREATE TABLE IF NOT EXISTS intel (
    cve_id TEXT PRIMARY KEY,
    epss_score REAL,
    epss_percentile REAL,
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS intel_string_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE,
    UNIQUE (cve_id, kind, value)
);

CREATE TABLE IF NOT EXISTS cpe_match (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    criteria TEXT NOT NULL,
    match_criteria_id TEXT,
    vulnerable INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cpe_match_cve ON cpe_match (cve_id);
-- ``cpe_match_unique`` (cve_id, criteria, match_criteria_id) is created by
-- :func:`vulnify.db.migrate.apply_sqlite_migrations` after deduping legacy rows.

CREATE TABLE IF NOT EXISTS reference (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    url TEXT,
    source TEXT,
    title TEXT,
    trust TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reference_cve ON reference (cve_id);

CREATE TABLE IF NOT EXISTS reference_tag (
    reference_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    FOREIGN KEY (reference_id) REFERENCES reference (id) ON DELETE CASCADE,
    UNIQUE (reference_id, tag)
);

CREATE TABLE IF NOT EXISTS tag (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS cve_tag (
    cve_id TEXT NOT NULL,
    tag_id INTEGER NOT NULL,
    PRIMARY KEY (cve_id, tag_id),
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tag (id) ON DELETE CASCADE
);

-- Per-phase resume state for cron-driven incremental runs. ``last_watermark``
-- is phase-specific: NVD stores the upper-bound ``lastModified`` of the last
-- successful refresh; KEV stores the catalog version it last ingested.
CREATE TABLE IF NOT EXISTS pipeline_run (
    phase TEXT PRIMARY KEY,
    last_completed_at TEXT NOT NULL,
    last_watermark TEXT
);

-- FTS5 index over CVE narrative text. External-content table tied to ``cve``
-- by rowid; backfill + sync handled by triggers below and the
-- ``_ensure_fts5_index`` migration. Used by the ``vulnify-mcp``
-- ``search_cves_text`` tool.
CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
    cve_id UNINDEXED,
    title,
    summary,
    technical_details,
    content='cve',
    content_rowid='rowid',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS cve_fts_ai AFTER INSERT ON cve BEGIN
    INSERT INTO cve_fts(rowid, cve_id, title, summary, technical_details)
    VALUES (new.rowid, new.cve_id, new.title, new.summary, new.technical_details);
END;

CREATE TRIGGER IF NOT EXISTS cve_fts_ad AFTER DELETE ON cve BEGIN
    INSERT INTO cve_fts(cve_fts, rowid, cve_id, title, summary, technical_details)
    VALUES ('delete', old.rowid, old.cve_id, old.title, old.summary, old.technical_details);
END;

CREATE TRIGGER IF NOT EXISTS cve_fts_au AFTER UPDATE ON cve BEGIN
    INSERT INTO cve_fts(cve_fts, rowid, cve_id, title, summary, technical_details)
    VALUES ('delete', old.rowid, old.cve_id, old.title, old.summary, old.technical_details);
    INSERT INTO cve_fts(rowid, cve_id, title, summary, technical_details)
    VALUES (new.rowid, new.cve_id, new.title, new.summary, new.technical_details);
END;
