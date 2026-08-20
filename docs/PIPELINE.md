# Pipeline

`vulnify-gather` builds and refreshes the database in two stages: **ingestion**
(the CVEProject spine) then **enrichment** (everything layered on top). Each
phase is independent, idempotent, watermarked, and individually skippable.

```
vulnify-gather
  │
  ├─ ingestion ──────── CVEProject cvelistV5 bulk zip → core CVE graph
  │
  └─ run_post_ingestion_enrichment
        ├─ kev          CISA Known Exploited Vulnerabilities
        ├─ nvd          NVD 2.0: CVSS, CPE, status, refs (incremental)
        ├─ vendor_index product_cpe_vendor rollup (local; needs nvd's cpe_match)
        ├─ epss         EPSS probability + percentile (batched)
        ├─ osv          OSV package mappings (per-CVE)
        ├─ nuclei       Nuclei templates   ┐
        ├─ exploitdb    Exploit-DB CSV     ├─ exploit_artefact + tri-state bools
        └─ metasploit   Metasploit modules ┘
```

See [DATASOURCES.md](DATASOURCES.md) for what each phase pulls and from where.

---

## Running it

```bash
uv run vulnify-gather            # full build/refresh
uv run vulnify-gather --skip-nvd # re-run everything except NVD
```

Skip flags (each maps to one phase; all idempotent):

```
-s / --skip-ingestion   --skip-kev    --skip-nvd    --skip-vendor-index
--skip-epss   --skip-osv    --skip-nuclei    --skip-exploitdb    --skip-metasploit
```

A cold build without an NVD API key takes **hours** — NVD's public rate limit
(~5 req / 30 s) is the bottleneck. A key raises it ~10×. See
[DATASOURCES.md](DATASOURCES.md#nvd-20-api).

**Print-only mode:** with `VULNIFY_SQLITE_PATH` empty/unset, the ingestion phase
parses but doesn't write — useful for exercising the parser without a DB.

---

## Watermarks & resume

Every phase records its progress in the `pipeline_run` table
(`phase`, `last_completed_at`, `last_watermark`). Re-runs are cheap because each
phase reads its own watermark and only does new work:

- **NVD** stores the upper-bound `lastModified` of its last successful refresh
  and pulls only CVEs modified since — incremental by design.
- **KEV** re-syncs in full but records the catalog version it last ingested.
- **EPSS** refreshes stale scores.
- **OSV** carries a per-CVE `osv_checked` marker, so completed lookups aren't
  repeated.
- **Exploit sources** store the corpus version (Nuclei commit SHA, Exploit-DB /
  Metasploit content hash); an unmoved corpus skips the parse.
- **vendor_index** is the exception: it records a watermark but **never resumes
  from it**. It is a local rollup of `affected_product` ⋈ `cpe_match`, both of
  which are cascade-wiped on re-ingest, and it is keyed by `product_id`. A full
  rebuild costs seconds, so there is nothing to gain by skipping it and a
  silently stale vendor index to lose. The watermark is for observability only.

An interrupted run picks up where it left off — no phase redoes finished work
just because a later phase crashed.

---

## Persistence: cascade + heal

The core write path **deletes and rebuilds** a CVE from the cvelistV5 document on
every ingest. `DeleteCveRowStep` runs `DELETE FROM cve WHERE cve_id = ?` with
`PRAGMA foreign_keys = ON`, so the delete **cascades to every child row** —
enrichment included (`exploit_artefact`, `intel`, `cvss`, `kev`, `cpe_match`, …).

Enrichment data therefore does **not survive** a re-ingest. It **heals**:

- **Exploit artefacts** are full-corpus local parses. They re-run in any gather
  where ingestion ran (unless a `--skip-*` flag overrides), restoring the wiped
  rows. Between the wipe and the heal, the summary bools read `null`, never a
  stale value.
- **OSV** heals for free — the `osv_checked` marker cascade-dies with the CVE, so
  the CVE re-pends for the next OSV pass.

**Consequences for consumers:** don't assume enrichment rows persist across a
re-ingest, and don't build long-lived external references to their integer
primary keys — they're rebuilt with fresh ids. Query by `cve_id`.

`vendor` and `product` rows are the exception: they hang off `vendor`, not `cve`,
so the cascade never reaches them and they accumulate forever. That cuts both
ways. A migration that *renames* or merges vendors is silently undone, because
`ensure_vendor` keys on exact `lower(trim(name))` and re-inserts the original
spelling straight back from the next gather's CVE JSON. And the `vendor_index`
phase, which repoints placeholder-owned products onto the vendor their CPE
evidence names, has to **merge** rather than `UPDATE`: `ensure_product` keys on
`(vendor_id, name, component)`, so a moved product no longer matches the lookup
and the next gather inserts a fresh duplicate under the placeholder — one per
gather, indefinitely. Merging into the existing twin means the phase re-converges
on each run instead of drifting.

The exploit write path deliberately runs **outside** `CveUpsertRegistry`:
artefacts are enrichment derived from external corpora, not part of the
cvelistV5 document graph, so the registry (which rebuilds rows *from* that
document) has nothing to rebuild them from. Persistence is handled by re-running
the phase, not by the write path.

---

## Tri-state exploit signals

`exploit.public_poc` and `exploit.metasploit` are **tri-state**, and the
distinction is the whole point of the exploit layer:

| Value | Meaning |
|--|--|
| `NULL` | **not assessed** — no contributing source has completed a run |
| `0` (`false`) | assessed, no artefact found |
| `1` (`true`) | assessed, at least one artefact exists |

Rules the pipeline holds to:

1. **Never collapse `null` → `false`.** "Not assessed" and "assessed, none found"
   are different answers. A fabricated or ungrounded PoC claim in a report is a
   liability; an honest "unknown" is not.
2. **Degradation is always toward `null`.** On re-ingest the bools reset to
   `null` (the model default) until healed — an under-claim, the safe direction.
   They only become `false` via phase-completion write-back, never any other path.
3. **All-contributing-sources rule.** A bool may be written `false` only once
   *every* source feeding it has completed ≥1 run: `public_poc` needs Nuclei
   **and** Exploit-DB; `metasploit` needs Metasploit. Until then it stays `null`.

The same discipline extends to version matching (a planned follow-on): verdicts
are three-state (`affected` / `not_affected` / `unknown`), version comparison is
**Python-side, never lexicographic SQL** (`"1.10" < "1.9"` is wrong), and
`not_affected` requires *complete* range coverage — not merely "nothing matched".

---

## Scheduling

The watermark model makes vulnify safe to run on a cron for incremental
refreshes: re-running `vulnify-gather` (or a subset via `--skip-*`) only fetches
what changed since each phase's last watermark. To cut a new data snapshot, bump
the pinned `cvelistV5` `ZIP_URL` in `providers/cveproject.py`, re-run, and
[cut a release](../README.md#releases).
