# vulnify

A CVE ingestion and enrichment pipeline that builds a single normalised SQLite
database stitched from CVEProject, NVD, CISA KEV, EPSS, and OSV — plus a
Streamlit explorer for the result.

Ships as a fully populated SQLite DB on each release so you don't have to wait
hours for the initial ingest.

---

## What's in it

- **Full CVE corpus** from the upstream CVEProject `cvelistV5` zip
- **NVD bulk merge** for CVSS metrics, CPE configurations, vuln status, and
  references
- **CISA Known Exploited Vulnerabilities** with `date_added`, `due_date`,
  ransomware flag, and required action
- **EPSS** exploit probability + percentile, batched
- **OSV** package mapping per CVE
- **Streamlit explorer** with ~70 pre-built views over the data
- **Resume-safe pipeline state** — interruptions pick up where they left off

Current snapshot (May 2026 release):

| | count |
|--|--:|
| CVEs | 347,248 |
| Vendors | 21,183 |
| Products | 70,266 |
| KEV entries | 1,586 |
| Tables | 20 |

---

## Documentation

Deeper references live in [`docs/`](docs/):

- **[Data sources](docs/DATASOURCES.md)** — every upstream feed, endpoint, and licence.
- **[Pipeline](docs/PIPELINE.md)** — ingestion → enrichment, watermarks/resume, the cascade+heal model, tri-state discipline.
- **[Schema](docs/SCHEMA.md)** — the 21-table layout and query gotchas.
- **[MCP server](docs/MCP.md)** — the 8 tools, per-agent setup, troubleshooting.
- **[Explorer](docs/EXPLORE.md)** — the Streamlit dashboard, tab by tab.

---

## Quick start (use the pre-built DB)

If you just want to query the data without running the pipeline:

```bash
# 1. Clone and pick the extras you need
git clone https://github.com/mez-0/vulnify.git
cd vulnify
uv sync --extra mcp          # for agents / MCP server
# or:  uv sync --extra explore   # for the Streamlit dashboard
# or:  uv sync --all-extras      # for everything

# 2. Grab the latest release DB
gh release download -R mez-0/vulnify --pattern vulnify.db.zst
zstd -d vulnify.db.zst -o vulnify.db

# 3. Point .env at the DB
cat > .env <<EOF
VULNIFY_SQLITE_PATH=$(pwd)/vulnify.db
VULNIFY_SCHEMA_SQL_PATH=vulnify/db/schema.sql
EOF

# 4a. Use it from an agent (see "MCP server" below for full setup)
uv run vulnify-mcp </dev/null     # smoke test — should start then exit on EOF

# 4b. Or browse it in the Streamlit explorer
uv run streamlit run explore/app.py

# 4c. Or just query the SQLite directly
sqlite3 vulnify.db "SELECT cve_id, summary FROM cve WHERE cve_id = 'CVE-2024-3094';"
```

---

## Building the DB from scratch

```bash
uv sync
cp .env.example .env       # edit paths as needed
uv run vulnify-gather
```

The first run takes **several hours** without an NVD API key (the public NVD
rate limit is ~5 requests / 30 seconds). With a key it's roughly 10x faster.

Get a free key at <https://nvd.nist.gov/developers/request-an-api-key> and set
`VULNIFY_NVD_API_KEY` in `.env`.

### Skipping phases

`vulnify-gather` exposes flags so you can re-run individual enrichment stages
without re-ingesting:

```bash
vulnify-gather --skip-ingestion        # don't re-download the CVEProject zip
vulnify-gather --skip-nvd              # skip NVD bulk merge
vulnify-gather --skip-vendor-index     # skip the product/CPE-vendor rollup
vulnify-gather --skip-kev              # skip CISA KEV
vulnify-gather --skip-epss             # skip EPSS batch
vulnify-gather --skip-osv              # skip OSV per-CVE lookups
vulnify-gather --skip-nuclei          # skip Nuclei exploit-template ingest
vulnify-gather --skip-exploitdb       # skip Exploit-DB artefact ingest
vulnify-gather --skip-metasploit      # skip Metasploit module-metadata ingest
```

The pipeline writes phase watermarks to the `pipeline_run` table, so re-runs
are idempotent — NVD only fetches changes since the last watermark, KEV
re-syncs in full, EPSS only updates stale scores.

The exploit phases (Nuclei / Exploit-DB / Metasploit) fetch and cache their
corpora under `~/.vulnify/cache` and watermark on corpus version (commit SHA /
content hash). They re-parse whenever cvelistV5 ingestion ran this gather — an
ingest cascade-deletes a re-touched CVE's artefacts, so they're healed on the
next run — and otherwise auto-skip an unmoved corpus. An explicit `--skip-*`
always wins. The tri-state `exploit.public_poc` / `exploit.metasploit` summary
bools are materialised from the artefacts: `null` until the contributing
sources have run, then `true`/`false`.

---

## Configuration

All config lives in `.env` at the project root (loaded by `vulnify.settings`).

| Variable | Required | Default | Purpose |
|--|:-:|--|--|
| `VULNIFY_SQLITE_PATH` | yes | `vulnify.db` | Where the SQLite DB lives. Empty/unset switches the CVEProject ingest to print-only mode. |
| `VULNIFY_SCHEMA_SQL_PATH` | yes | `vulnify/db/schema.sql` | DDL used to bootstrap a new DB. |
| `VULNIFY_KEV_JSON_PATH` | no | `known_exploited_vulnerabilities.json` | Where the CISA KEV catalog is cached. The KEV phase downloads it there and refreshes it once it is a day old. |
| `VULNIFY_NVD_API_KEY` | no | — | NVD API key. Without it you're rate-limited to ~5 req / 30s. |
| `VULNIFY_CACHE_DIR` | no | `~/.vulnify/cache` | Where the exploit corpora (Nuclei / Exploit-DB / Metasploit) are cached; each is re-downloaded once a day old. |

Relative paths are resolved against the project root.

---

## Architecture

```
                  ┌───────────────────┐
                  │  gather.py (CLI)  │
                  └─────────┬─────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │   providers/cveproject.py   │  bulk download + parse
              └──────────────┬──────────────┘
                             │
                             ▼
              ┌─────────────────────────────┐
              │   db/sqlite_store.py        │  upsert into normalised tables
              └──────────────┬──────────────┘
                             │
                             ▼
         ┌───────────────────┴────────────────────┐
         │   providers/enrichment.py              │
         │   ├── cisa_kev   (CISA KEV catalog)    │
         │   ├── nvd        (CVSS, CPE, status)   │
         │   ├── epss       (probability scores)  │
         │   ├── osv        (package mappings)    │
         │   └── exploit_ingest (Nuclei/EDB/MSF)  │
         └────────────────────┬───────────────────┘
                              │
                              ▼
         ┌────────────────────┴────────────────────┐
         ▼                                         ▼
┌───────────────────────────────┐   ┌───────────────────────────────┐
│   explore/app.py (Streamlit)  │   │   vulnify/mcp.py (FastMCP)    │
└───────────────────────────────┘   └───────────────────────────────┘
```

### Source layout

```
vulnify/
├── vulnify/
│   ├── gather.py             # `vulnify-gather` CLI (ingestion + enrichment)
│   ├── mcp.py                # `vulnify-mcp` FastMCP server (stdio)
│   ├── settings.py           # .env loader + path resolvers
│   ├── constants.py          # Severity, SourceTrust, ExploitMaturity enums
│   ├── cvss_severity.py      # CVSS-base -> severity bucketing
│   ├── http.py               # shared httpx client + file/zip download helpers
│   ├── models/               # dataclass models (CVE, Vendor, Product, CVSS, …)
│   ├── providers/
│   │   ├── cveproject.py     # CVEProject bulk parser
│   │   ├── nvd.py            # NVD 2.0 API client + per-CVE merge
│   │   ├── cisa_kev.py       # KEV catalog ingest
│   │   ├── epss.py           # FIRST EPSS batch enrichment
│   │   ├── osv.py            # OSV per-CVE package lookup
│   │   ├── exploit_ingest.py # Nuclei/Exploit-DB/Metasploit artefact ingest
│   │   ├── vendor_advisories.py
│   │   ├── enrichment.py     # phase orchestrator
│   │   └── enrichment_resume.py
│   └── db/
│       ├── schema.sql        # 21-table normalised schema + FTS5 index
│       ├── sqlite_store.py   # connection + upsert API
│       ├── readonly.py       # shared read-only sqlite3 helper
│       ├── cve_upsert.py     # CVE/vendor/product writes
│       ├── migrate.py        # idempotent migrations + FTS5 backfill
│       ├── pipeline_state.py # phase watermarks
│       └── sql_conversion.py # model <-> row helpers
├── explore/
│   ├── app.py                # Streamlit dashboard
│   ├── data.py               # overview queries
│   └── data_views.py         # per-chart queries
└── tests/                    # pytest suite (no network, no real DB)
```

---

## Schema overview

20 tables, all normalised, foreign keys enabled. Top-level CVE plus separate
tables for the high-cardinality bits (CPE matches, references, CVSS metrics,
exploit signals + artefacts, KEV listing, intel) so you can join cleanly.

```
cve                — primary CVE record
vendor             — deduped vendors (case/whitespace-normalised)
product            — products owned by a vendor
cve_vendor         — many-to-many with `role` (assigner, affected, source, …)
affected_product   — CVE <-> product affected/not-affected with notes
version_range      — per affected_product version constraints
cwe / cve_cwe      — weakness taxonomy
cvss               — every CVSS vector from any source, deduped on (source, version, vector)
cpe_match          — NVD configuration leaf matches
exploit            — exploit availability + maturity (tri-state summary bools)
exploit_artefact   — per-CVE exploit evidence (Nuclei/Exploit-DB/Metasploit)
kev                — CISA KEV listing fields per CVE
intel              — generic threat-intel rows (kind/value/source)
intel_string_list  — backing list values for intel rows
reference          — URL references with trust + source
reference_tag      — many-to-many for ref tag vocabulary
tag / cve_tag      — CVE-level tags
pipeline_run       — per-phase watermarks for resume
```

Full DDL is in [`vulnify/db/schema.sql`](vulnify/db/schema.sql); an annotated
walkthrough with query gotchas is in [docs/SCHEMA.md](docs/SCHEMA.md).

---

## MCP server (`vulnify-mcp`)

`vulnify.mcp` exposes the SQLite database to AI agents over the
[Model Context Protocol](https://modelcontextprotocol.io). It's a FastMCP
server speaking stdio, so agents like Claude Code, Claude Desktop, and
Cursor spawn it as a subprocess on demand.

> Full tool reference, per-agent setup, and troubleshooting:
> **[docs/MCP.md](docs/MCP.md)**.

### Step 1 — set up the project

```bash
git clone https://github.com/mez-0/vulnify.git
cd vulnify
uv sync --extra mcp
```

### Step 2 — get a SQLite database

Two options:

**Option A — pre-built (recommended).** Download the release asset and
decompress:

```bash
gh release download -R mez-0/vulnify --pattern vulnify.db.zst
zstd -d vulnify.db.zst -o vulnify.db
```

**Option B — build from source.** Takes hours; see [Building the DB from
scratch](#building-the-db-from-scratch).

### Step 3 — point the server at the DB

Create `.env` at the project root with an absolute path:

```bash
echo "VULNIFY_SQLITE_PATH=$(pwd)/vulnify.db" > .env
echo "VULNIFY_SCHEMA_SQL_PATH=vulnify/db/schema.sql" >> .env
```

### Step 4 — smoke test

Confirm the server starts and shuts down cleanly. It speaks stdio, so just
sending `Ctrl-D` (EOF) exits it:

```bash
uv run vulnify-mcp </dev/null
```

If you used a release DB built before FTS5 shipped, you'll see a one-off
~8 second backfill on stderr:

```
INFO   Backfilling FTS5 index over 347248 CVE rows — one-off, takes ~30s
INFO   FTS5 backfill complete in 8.5s
```

That's it — releases from `v2026.05.21.1` onwards ship with the FTS index
pre-built, so this step is silent.

### Step 5 — wire it into your agent

#### Claude Code

Easiest is the CLI:

```bash
claude mcp add vulnify \
  --scope user \
  -- uv run --directory "$(pwd)" vulnify-mcp
```

Or edit `~/.claude.json` directly:

```json
{
  "mcpServers": {
    "vulnify": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/vulnify", "vulnify-mcp"]
    }
  }
}
```

Verify it's connected:

```bash
claude mcp list
```

#### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "vulnify": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/vulnify", "vulnify-mcp"]
    }
  }
}
```

Restart Claude Desktop after editing.

#### Cursor

Edit `~/.cursor/mcp.json` (or the project-local `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "vulnify": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/vulnify", "vulnify-mcp"]
    }
  }
}
```

### Tools the agent can call

| Tool | What it does |
|--|--|
| `get_cve(cve_id)` | Full hydrated CVE record — CVSS, KEV, EPSS, exploits, references, CWEs, affected products, plus an `artefacts` evidence list. |
| `search_cves(...)` | Filter by vendor / product / cwe / kev_only / min_cvss / min_epss / year. The `vendor` filter resolves four ways (vendor edge, product owner, product name, CPE vendor slug) — see [MCP.md](docs/MCP.md#how-the-vendor-filter-resolves). |
| `list_vendors(query, limit)` | Vendor names with CVE / product counts and their NVD CPE slugs. Use it to disambiguate a vendor term before trusting an empty result. |
| `exploits_for(cve_id)` | Concrete exploit artefacts (Nuclei / Exploit-DB / Metasploit) with source, stable id, url, and `exact`/`parsed` confidence. |
| `references_for(cve_id, tag)` | Reference URLs with their tags, optionally filtered to one tag (e.g. `patch`, `exploit`). |
| `list_kev(since, limit)` | Recent CISA KEV entries, newest first. |
| `database_overview()` | Totals, published-date range, last pipeline-run times. |
| `search_cves_text(query, limit)` | FTS5 free-text search over title / summary / technical details. AND / OR / NOT / quoted phrases / `prefix*` all supported. |

All tools return JSON-serialisable dicts. Limits cap at 100 rows.

### Example agent prompts

- "What's CVE-2024-3094?"
- "Show me KEV entries added in the last 60 days about Cisco."
- "Find CVEs about container escape with CVSS ≥ 8."
- "Which products have the most CVEs published in 2025?"

### Troubleshooting

- **Tools don't show up in an already-running agent** — MCP servers are
  attached at session start, not when `claude mcp add` runs. Exit your
  current Claude Code / Cursor session and start a fresh one — don't
  `/resume` an old one, that re-reads the old tool list.
- **`claude mcp list` shows `✗ Failed to connect`** — first thing to
  check is the exact `Args:` field with `claude mcp get vulnify`; a
  copy-paste truncation that turns `vulnify-mcp` into `vulnify-mc` is
  a common one. Smoke test the spawned command verbatim in a shell:
  `uv run --directory /path/to/vulnify vulnify-mcp </dev/null`.
- **`uv: command not found`** in the agent's process — agents inherit a
  minimal `PATH`. Either use an absolute path to `uv` in the config
  (`command: "/home/you/.cargo/bin/uv"`) or symlink `uv` into
  `/usr/local/bin`.
- **`VULNIFY_SQLITE_PATH is unset`** at startup — your `.env` isn't being
  picked up. The server resolves `.env` relative to the vulnify package
  root; pass an absolute `--directory` in the agent config so it lands in
  the right place.
- **Tool calls return nothing** — confirm the DB has data with
  `uv run python -c "import sqlite3; print(sqlite3.connect('vulnify.db').execute('SELECT COUNT(*) FROM cve').fetchone())"`.
- **Logs disappearing** — `vulnify-mcp` logs to stderr (so it doesn't
  corrupt the MCP protocol on stdout). Most agent UIs surface stderr in
  their MCP logs view; in Claude Code that's `/mcp` then pick the server.

---

## Explorer

`explore/app.py` is a Streamlit dashboard with roughly 70 pre-built views over
the data: severity distributions, KEV listing lag, EPSS density, CWE
co-occurrence heatmaps, vendor / product pressure, CVSS vector breakdowns,
publication recency, exploit-in-the-wild monthly trends, and more.

```bash
uv sync --extra explore
uv run streamlit run explore/app.py
```

Views are organised into 14 tabs (Overview, Vendors, Trends, Vendor links,
Severity & CWE, Enrichment, Exploit landscape, KEV deep dive, CVSS vector,
Products & CPEs, References, Threat intel, Lifecycle, Pipeline health) and split
across two query modules: `explore/data.py` (overview / landing) and
`explore/data_views.py` (the per-chart queries). Full tab-by-tab breakdown and
how to add a view: **[docs/EXPLORE.md](docs/EXPLORE.md)**.

---

## Tests

```bash
uv run pytest
```

Tests are hermetic — no network, no real DB. They cover:

- SQLite store upsert + dedup behaviour
- Schema migration + backfill
- NVD bulk merge
- Pipeline state watermarks
- Enrichment resume logic
- Explorer query shapes
- MCP tool surface (structured + FTS5 search)

---

## Releases

Each release ships:

- **`vulnify.db.zst`** — the full SQLite DB, zstd-compressed. Includes the
  FTS5 index pre-built from `v2026.05.21.1` onwards, and the
  `product_cpe_vendor` vendor index pre-built from `v2026.07.25.1` onwards, so
  `vulnify-mcp` is ready to serve immediately on first start rather than
  spending ~40s building them. Decompress with `zstd -d vulnify.db.zst`.
- **`schema.sql`** — the DDL, in case you only want the structure.

Tag scheme:

- **`vYYYY.MM.DD`** — major snapshot, data captured on that date.
- **`vYYYY.MM.DD.N`** — code patch against the same data snapshot
  (e.g. `v2026.05.21.1` is the `2026-05-21` data with the `vulnify-mcp`
  server added).

The code version in `pyproject.toml` follows SemVer independently.

---

## License

Released under the [MIT License](LICENSE).
