# Schema

20 normalised tables plus an FTS5 virtual table. Foreign keys are enabled at the
application layer (`PRAGMA foreign_keys = ON`) — the top-level `cve` row is the
parent, and **every child table cascades on delete**. That cascade is
load-bearing for the pipeline's persistence model (see
[PIPELINE.md](PIPELINE.md#persistence-cascade--heal)).

Full DDL: [`vulnify/db/schema.sql`](../vulnify/db/schema.sql). Additive
migrations and the FTS5 backfill live in `vulnify/db/migrate.py`.

---

## Core

**`cve`** — the primary record, keyed by `cve_id`. Holds title, `cna`, `summary`,
`technical_details`, `published` / `modified` / `discovered`, `vuln_status`
(NVD), `state`, `assigner_org_id`, `source_identifier`, and derived
`priority_score` / `confidence`. Every other table hangs off this `cve_id`.

## Vendors & products

- **`vendor`** — deduped vendors; `UNIQUE` on `lower(trim(name))` so casing and
  whitespace can't create duplicates.
- **`cve_vendor`** — CVE ↔ vendor many-to-many with a `role`
  (`assigner` / `affected` / `source` / …). PK `(cve_id, vendor_id, role)`.
- **`product`** — products owned by a vendor; `UNIQUE (vendor_id, name, component)`.
- **`affected_product`** — CVE ↔ product with an `affected` flag (1 = affected,
  0 = explicitly not) and free-text `notes`.
- **`version_range`** — per-`affected_product` version constraints:
  `start_including` / `start_excluding` / `end_including` / `end_excluding`,
  `fixed_version`, and the original `raw_text`.

## Weakness taxonomy

- **`cwe`** — CWE id, name, description.
- **`cve_cwe`** — CVE ↔ CWE many-to-many.

## Scoring & intel

- **`cvss`** — every CVSS vector from any source, one row each: `version`,
  `score`, `vector`, `severity`, the decomposed metrics (attack vector/complexity,
  privileges, UI, scope, CIA), `exploitability_score`, `impact_score`, and
  `metric_source` / `metric_type`. Deduped on `(source, version, vector)`. A CVE
  can carry both a CNA and an NVD vector — query `MAX(score)` for the worst case.
- **`intel`** — one row per CVE: `epss_score`, `epss_percentile` (from EPSS).
- **`intel_string_list`** — generic backing list values keyed `(cve_id, kind, value)`;
  where OSV package mappings land.

## Exploitation

- **`exploit`** — one **summary** row per CVE. `maturity`, the tri-state bools
  `public_poc` / `metasploit` (`NULL` = not assessed, 0 = none found, 1 = found —
  see [tri-state](PIPELINE.md#tri-state-exploit-signals)), and the
  NVD/KEV-sourced flags `ransomware_usage` / `in_the_wild`.
- **`exploit_artefact`** — the **evidence** layer: many artefacts per CVE
  (`source`, `stable_id`, `url`, `artefact_type`, `platform`, `published_date`,
  `confidence`). `confidence` is a provenance vocab (`exact` / `parsed` /
  `heuristic`), enforced in the ingest layer, not a CHECK constraint.
  `UNIQUE (cve_id, source, stable_id)` keeps re-ingest upserts idempotent and
  serves `WHERE cve_id = ?` via its leftmost column. Written by direct SQL
  **outside** the cvelistV5 upsert graph — so a CVE re-ingest cascade-wipes these
  and they heal on the next exploit-phase run.
- **`kev`** — CISA KEV listing, **one row per CVE** with a `listed` flag (not one
  row per catalog entry). `date_added`, `due_date`, `required_action`,
  `vulnerability_name`, vendor/product labels, `short_description`. **Count listed
  entries with `WHERE listed = 1`** — `COUNT(*)` counts every CVE.

## Applicability

- **`cpe_match`** — NVD configuration leaf matches: `criteria` (the CPE 2.3
  string), `match_criteria_id`, `vulnerable` flag. `cpe_match_unique`
  `(cve_id, criteria, match_criteria_id)` is created by the migration after
  deduping legacy rows.

## References & tags

- **`reference`** — URL references with `source`, `title`, `trust`.
- **`reference_tag`** — tags per reference, keyed by `reference_id`. **No
  `cve_id` column** — join through `reference`:
  `reference JOIN reference_tag ON reference_tag.reference_id = reference.id`.
- **`tag`** / **`cve_tag`** — CVE-level tag vocabulary and its many-to-many.

## Pipeline

- **`pipeline_run`** — per-phase resume state: `phase` (PK), `last_completed_at`,
  `last_watermark` (phase-specific — NVD stores an upper-bound `lastModified`;
  KEV stores the catalog version; exploit sources store a corpus commit SHA /
  content hash). See [PIPELINE.md](PIPELINE.md).

## Full-text search

- **`cve_fts`** — FTS5 virtual table (external-content, tied to `cve` by rowid)
  over `title` / `summary` / `technical_details`, tokenised `porter unicode61`.
  Kept in sync by insert/update/delete triggers on `cve`; backfilled once by the
  `_ensure_fts5_index` migration on older DBs. Powers the MCP `search_cves_text`
  tool. (FTS5 also creates internal shadow tables — `cve_fts_data`, `_idx`, etc. —
  which don't count toward the 20.)

---

## Query notes

- **Worst-case CVSS per CVE:** `SELECT MAX(score) FROM cvss WHERE cve_id = ?` —
  a CVE may have several vectors from different sources.
- **KEV count:** `WHERE listed = 1`, never bare `COUNT(*)`.
- **Reference tags:** join via `reference.id`, not a `cve_id` on `reference_tag`.
- **Exploit tri-state:** filter `public_poc IS NOT NULL` before treating the
  value as boolean, or you'll conflate "not assessed" with "none found".
- Enrichment rows (`exploit_artefact`, `intel`, `cpe_match`, `cvss`, `kev`) are
  cascade-deleted when their `cve` row is re-ingested — they are *rebuilt*, not
  preserved. Don't build long-lived external references to their integer PKs.
