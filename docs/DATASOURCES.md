# Data sources

vulnify stitches one normalised CVE corpus from eight public sources. Each is an
independent [pipeline phase](PIPELINE.md) with its own watermark and `--skip-*`
flag, so any source can be refreshed — or skipped — on its own.

`cvelistV5` is the **spine**: it defines which CVEs exist and seeds the core
graph. Everything else is **enrichment** layered on top of CVEs that already
exist.

| Source | Phase | Endpoint | Contributes | Refresh model |
|--|--|--|--|--|
| **CVEProject `cvelistV5`** | `ingestion` | GitHub release zip (dated snapshot) | `cve`, `vendor`, `product`, `cve_vendor`, `affected_product`, `version_range`, `cwe`, `cve_cwe`, `reference`, CNA-sourced `cvss` | Full re-parse of the bulk zip |
| **NVD 2.0** | `nvd` | `services.nvd.nist.gov/rest/json/cves/2.0` | NVD-sourced `cvss`, `cpe_match`, `cve.vuln_status`, extra `reference` rows | Incremental by `lastModified` watermark |
| **CISA KEV** | `kev` | Local JSON snapshot | `kev` (+ feeds `exploit.in_the_wild` / `ransomware_usage`) | Full re-sync; watermark = catalog version |
| **EPSS (FIRST)** | `epss` | `api.first.org/data/v1/epss` | `intel.epss_score`, `intel.epss_percentile` | Batched; stale scores refreshed |
| **OSV** | `osv` | `api.osv.dev/v1/vulns/{id}` | `intel_string_list` (package mappings) | Per-CVE; `osv_checked` markers gate re-fetch |
| **Nuclei templates** | `nuclei` | `codeload.github.com/projectdiscovery/nuclei-templates` | `exploit_artefact` (`source=nuclei`) → `public_poc` | Watermark = commit SHA |
| **Exploit-DB** | `exploitdb` | `gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | `exploit_artefact` (`source=exploitdb`) → `public_poc` | Watermark = content hash |
| **Metasploit** | `metasploit` | `raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json` | `exploit_artefact` (`source=metasploit`) → `metasploit` | Watermark = content hash |

Exploit corpora are cached under `VULNIFY_CACHE_DIR` (default `~/.vulnify/cache`)
and re-downloaded once the copy is a day old (`vulnify.http.fetch_cached`); a
failed refresh falls back to the stale copy with a warning. The watermark is
taken from the file actually parsed, so an unmoved corpus still skips the parse.

---

## CVEProject `cvelistV5` — the spine

The authoritative CVE record set (CNA-submitted). Ingested as a single bulk zip
pulled from a **dated GitHub release** — the URL in `providers/cveproject.py`
(`ZIP_URL`) is pinned to a specific snapshot date and must be bumped to refresh
the base corpus. The zip and its extracted tree are cached in `/tmp`, each with
a marker recording the `ZIP_URL` that produced it; a missing or different
marker discards the cache, so bumping the pin always takes effect.

Seeds the core graph: the CVE row, its vendors/products (deduped, case- and
whitespace-normalised), affected-product version ranges, CWE weakness links,
CNA-provided CVSS vectors, and references with trust/source tags. With
`VULNIFY_SQLITE_PATH` empty, this phase runs in **print-only mode** (parse, no
write) — handy for smoke-testing the parser.

## NVD 2.0 API

Adds the NVD's own analysis on top of the CNA record: NVD-scored CVSS metrics,
CPE applicability configurations (`cpe_match`), vulnerability status, and extra
references. Refreshes **incrementally** — the `nvd` watermark stores the
upper-bound `lastModified` of the last successful run, so subsequent runs only
pull CVEs modified since.

**Rate limits:** ~5 requests / 30 s without a key; ~50 / 30 s with one. Set
`VULNIFY_NVD_API_KEY` in `.env` (free from
<https://nvd.nist.gov/developers/request-an-api-key>) for the ~10× speed-up. A
cold build without a key takes hours; this phase is the bottleneck.

## CISA KEV

The Known Exploited Vulnerabilities catalog — CVEs CISA has confirmed are
exploited in the wild. Fetched from CISA's JSON feed into
`VULNIFY_KEV_JSON_PATH` (default `known_exploited_vulnerabilities.json`) and
refreshed once that copy is a day old. Merged into existing CVEs in place by
direct SQL — never the delete-and-rebuild upsert, which would cascade away
their exploit artefacts. Populates `date_added`, `due_date`, required action,
ransomware flag, and vendor/product labels. The `kev` phase re-syncs in full;
the watermark records the catalog version last ingested.

> The `kev` table stores **one row per CVE** with a `listed` flag, not one row
> per catalog entry. Count listed entries with `WHERE listed = 1`.

## EPSS (FIRST)

The Exploit Prediction Scoring System — a daily-updated probability (0–1) that a
CVE will be exploited in the next 30 days, plus its percentile. Fetched in
batches into `intel`. The `epss` phase refreshes stale scores.

## OSV

Open Source Vulnerabilities — maps CVEs to affected packages by ecosystem
(PyPI, npm, Go, …). Queried **per CVE**; a CVE carries an `osv_checked` marker
so completed lookups aren't repeated. Because those markers cascade-delete with
the CVE on re-ingest, a re-ingested CVE is automatically re-queried on the next
`osv` pass (see [PIPELINE.md](PIPELINE.md#persistence-cascade--heal)).

## Exploit corpora → `exploit_artefact`

Three sources contribute concrete exploit **evidence** rows, each with a
provenance `confidence` grade (not a quality score):

- **Nuclei templates** — CVE-tagged detection templates from
  `projectdiscovery/nuclei-templates`. Confidence `exact` (CVE id read from the
  template's `classification.cve-id`). Watermark is the commit SHA (from the
  GitHub API, since the tarball bytes shift per download).
- **Exploit-DB** — the offline `files_exploits.csv` mirror. Confidence `parsed`
  (CVE ids extracted from the free-text refs column). Watermark is the file's
  content hash.
- **Metasploit** — module metadata (`modules_metadata_base.json`). Confidence
  `exact` (CVE ids from module `References`). Watermark is the content hash.

These feed the tri-state summary bools on `exploit`: `public_poc` from Nuclei +
Exploit-DB, `metasploit` from Metasploit modules. See the tri-state discipline in
[PIPELINE.md](PIPELINE.md#tri-state-exploit-signals).

---

## Attribution & licensing

vulnify redistributes derived data from third parties. Their terms govern that
data — vulnify's MIT licence covers the **code**, not the upstream datasets:

- **CVE® / cvelistV5** — a registered trademark of MITRE; CVE records are
  published under CVE Program terms.
- **NVD** — a U.S. Government work (NIST); public domain, no key required to use
  the data.
- **CISA KEV** — U.S. Government work; public domain.
- **EPSS** — provided by FIRST.org, free to use with attribution.
- **Nuclei templates** — ProjectDiscovery, MIT.
- **Exploit-DB** — OffSec; the offline CSV is redistributable, individual
  exploits carry their own terms.
- **Metasploit Framework** — Rapid7, BSD-3-Clause.

If you redistribute a built DB, carry these attributions with it.
