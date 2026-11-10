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
        ├─ nvd          NVD 2.0: CVSS, CPE, status, refs (incremental; full after an ingest)
        ├─ placeholder_products  give `n/a` CVEs every product their vulnerable CPEs name (local)
        ├─ vendor_index product_cpe_vendor + per-CVE cve_cpe_vendor (local; needs nvd's cpe_match)
        ├─ product_candidates    opt-in description-named products for what's left (local)
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
-s / --skip-ingestion   --skip-kev    --skip-nvd    --skip-placeholder-products
--skip-vendor-index   --skip-product-candidates   --skip-epss   --skip-osv
--skip-nuclei    --skip-exploitdb    --skip-metasploit
```

A full gather takes **4–5 hours** without an NVD API key. Measured on two
builds with ingestion running (the product-identity phases on the first are
from a trial run against a copy of it):

| Phase | 2026-11-02 build | 2026-11-10 build |
|-------|-----:|-----:|
| cvelistV5 download + ingest | ~25 min | 24 min |
| NVD bulk (full backfill, no key) | ~63 min | 31 min |
| placeholder products | ~25 s | 22 s |
| vendor index | ~2 min | 1.6 min |
| product candidates | ~4 s | 3 s |
| EPSS | ~48 min | 42 min |
| **OSV** | **~2 h 45 min** | **2 h 34 min** |
| Nuclei + Exploit-DB + Metasploit | ~1 min | ~1 min |
| **Total** | **~5 h** | **4 h 15 min** |

NVD halving between two keyless runs is NVD's response time, not a code change.

OSV is the long pole after an ingest, not NVD: the ingest cascade-wipes every
`osv_checked` marker, so all CVEs are re-queried. A gather without ingestion is
much shorter. An NVD key raises NVD's rate limit ~10×, but only the inter-page
sleep shrinks, not the fetch and merge time. See
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
- **Exploit sources** store the corpus version (Nuclei tarball commit SHA, Exploit-DB /
  Metasploit content hash); an unmoved corpus skips the parse.
- **NVD** ignores its watermark whenever ingestion ran this gather — see
  [cascade + heal](#persistence-cascade--heal).
- **placeholder_products** and **product_candidates** record a watermark but
  never resume from it, for the same reason as vendor_index below: they write
  from `affected_product` rows that the next ingest rebuilds onto the placeholder.
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
- **NVD** and **KEV** heal only because ingestion forces them past their
  watermarks: NVD runs a full backfill and KEV re-ingests an unchanged catalog
  whenever ingestion ran. Without that, an incremental NVD refresh re-fetches
  only what *NVD* modified since, and the rest stays wiped — a gather after a
  snapshot bump once left `cpe_match` at 169k rows of 1.3M.
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

### Product identity: CNA, then CPE, then (opt-in) prose

A CNA that writes `"product": "n/a"` leaves its CVE on one shared placeholder
product, unreachable by any vendor or product filter. Three layers recover it,
strongest evidence first, and each row says which one it came from:

| Layer | Written to | `affected_product.source` | Coverage (2026-11-10 build) |
|-------|-----------|---------------------------|-----------------------------|
| cvelistV5 record names it | `affected_product` | `cna` | 474,885 rows |
| `placeholder_products` phase: every `(vendor, product)` its **vulnerable** CPEs name | `affected_product` (+ `affected` `cve_vendor` edges) | `cpe` | 140,397 CVEs, 249,593 rows (the old one-pair rule reached ~99,800) |
| `product_candidates` phase: `<vendor> <product>` named in the title/summary | `product_candidate` **only** | — | 543 of the 4,129 still unidentified (686 rows) |

- **Fan out, never pick.** A multi-product CVE gets one row per vulnerable CPE
  pair. The earlier rule resolved only CVEs naming exactly one pair; it avoided
  a guess by resolving nothing and left 40,643 CVEs invisible (D-Link alone had
  989 of its 1,872 CVEs hidden).
- **`vulnerable = 1` only.** Platform CPEs (the Windows an app runs on, the
  hardware beside its `_firmware`) are not what the CVE affects. One exception:
  a CVE with no vulnerable CPE and exactly one pair resolves to it — NVD's
  2003–2005 records flag the affected product itself non-vulnerable (357 CVEs).
- **The vendor index counts a `cpe` row's own vendor only.** Counting every
  vendor on a fanned-out CVE pushed PAN-OS past the slug cap and out of the
  index. The share floor still dilutes distro slugs on busy products (`git`'s
  `fedoraproject` fell from 5.7% to 3.5%), which cost 178 CVEs whose own
  vulnerable CPEs name the vendor.
- **`cve_cpe_vendor` closes that per CVE.** One edge per vendor a CVE's own
  vulnerable CPEs name (365,513 edges), read as the fifth vendor-search branch.
  It restored all 178 and found 13,661 CVEs across 50 vendors no vendor search
  had ever returned (Debian +3,566, Google +3,013 mostly Android filed under
  `n/a`, Fedora +2,123). Built in ~10s inside the `vendor_index` phase.
- **Candidates never reach `affected_product`.** They are guesses (~7% wrong
  vendor, measured against CPE); `search_cves` ignores them and `get_cve` labels
  them. Precision table and rules: `vulnify/db/product_candidates.py`.
- **What's left** (~3,600 CVEs, mostly 2024–2026 NVD backlog/`Deferred`) is
  reachable only by full-text search. Use a prefix query: a product written
  with its version glued on (`Relay3`) is one token, so `relay` misses it and
  `relay*` finds it.

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
