# CLAUDE.md — vulnify

Guidance for Claude (and humans) working in this repo. Read it before touching
the pipeline, the schema, or the MCP surface.

## Documentation

Deep-dive docs live in [`docs/`](docs/) — read the relevant one before working in that area:

- **[docs/DATASOURCES.md](docs/DATASOURCES.md)** — the eight upstream sources, endpoints, what each contributes, licensing.
- **[docs/PIPELINE.md](docs/PIPELINE.md)** — ingestion → enrichment flow, watermarks/resume, the cascade+heal persistence model, tri-state discipline.
- **[docs/SCHEMA.md](docs/SCHEMA.md)** — the 20-table schema, relationships, query gotchas.
- **[docs/MCP.md](docs/MCP.md)** — the `vulnify-mcp` server, its 7 tools, setup, troubleshooting.
- **[docs/EXPLORE.md](docs/EXPLORE.md)** — the Streamlit explorer.

---

## What vulnify is

A CVE **ingestion + enrichment pipeline** that stitches several public sources
into one normalised SQLite database, plus two consumers of it:

- **`vulnify-mcp`** — a FastMCP (stdio) server exposing the DB to AI agents. The primary product.
- **`explore/app.py`** — a Streamlit dashboard (~70 views).

The DB is **the deliverable**: built offline (hours), then shipped
fully-populated as a zstd-compressed release asset so consumers never run the
pipeline themselves. The pipeline exists to *build and refresh* that DB.

**Use case:** offensive/defensive triage. "Does a real exploit exist for this
CVE and where?" "What's in KEV about Cisco this month?" "Find container-escape
CVEs with CVSS ≥ 8." The value is a single joinable corpus with exploit evidence
and provenance — not another API wrapper.

---

## Golden rules

1. **Python is always `uv`.** `uv sync`, `uv run …`, `uv add …`. Never pip/poetry/conda. Pinned to **3.13+**.
2. **Tri-state is a hard invariant.** `exploit.public_poc` / `exploit.metasploit` are nullable: `null` = never assessed, `false` = assessed & nothing found, `true` = found. **Never collapse `null` → `false`.** Degradation always trends toward `null` (under-claim). Full rules in [PIPELINE.md](docs/PIPELINE.md#tri-state-exploit-signals).
3. **Version comparison is Python-side, never SQL.** Lexicographic SQL is wrong (`"1.10" < "1.9"`). Verdicts are three-state; `not_affected` requires *complete* range coverage.
4. **Tests are hermetic.** No network, no real DB, no mocking library — tempfile DBs + fixture dicts. Keep them that way.
5. **The DB is never committed.** Gitignored (`*.db`, `*.db.zst`), shipped via releases. Same for `docs/features/` (internal `/dev`-suite planning — kept local, never shipped).

---

## Commands

```bash
uv sync                        # core deps
uv sync --extra mcp            # + MCP server
uv sync --extra explore        # + Streamlit dashboard
uv sync --all-extras           # everything (incl. dev/pytest)

uv run vulnify-gather          # build/refresh the DB (ingest + enrich)
uv run vulnify-mcp             # start the MCP server (stdio)
uv run vulnify-mcp </dev/null  # smoke test — starts, exits clean on EOF
uv run streamlit run explore/app.py
uv run pytest                  # hermetic suite (currently 73 tests, ~2s)
```

Entry points: `vulnify-gather` → `vulnify.gather:run`, `vulnify-mcp` → `vulnify.mcp:run`.

Pipeline skip flags (each = one phase, all idempotent) — see [PIPELINE.md](docs/PIPELINE.md#running-it):

```
-s / --skip-ingestion   --skip-kev   --skip-nvd   --skip-epss
--skip-osv   --skip-nuclei   --skip-exploitdb   --skip-metasploit
```

---

## Architecture

```
vulnify/
├── gather.py            # `vulnify-gather` CLI — ingest then enrich
├── mcp.py               # `vulnify-mcp` FastMCP server (stdio), 7 tools
├── settings.py          # .env loader + path resolvers (relative → project root)
├── constants.py         # Severity / SourceTrust / ExploitMaturity / ProductType enums
├── cvss_severity.py     # CVSS base score → severity bucket
├── http.py              # shared httpx client + download helpers
├── models/              # dataclasses (CVE, Vendor, Product, CVSS, ExploitInfo, …)
├── providers/           # one flat file per source (kev, nvd, epss, osv, cveproject,
│   │                    #   exploit_ingest [nuclei+edb+msf], vendor_advisories)
│   ├── enrichment.py    # run_post_ingestion_enrichment — phase orchestrator
│   └── enrichment_resume.py
└── db/
    ├── schema.sql       # 20-table normalised schema + FTS5 index
    ├── sqlite_store.py  # connection + upsert API (WAL, foreign_keys ON)
    ├── cve_upsert.py    # CVE/vendor/product write registry (delete-and-rebuild)
    ├── migrate.py       # idempotent additive migrations + FTS5 backfill
    ├── pipeline_state.py# per-phase watermark read/write
    ├── readonly.py      # read-only sqlite helper (NOTE: currently unused by mcp.py)
    └── sql_conversion.py# model ↔ row helpers
```

Config lives in `.env` (loaded by `vulnify.settings`); relative paths resolve
against the project root. Vars: `VULNIFY_SQLITE_PATH` (req), `VULNIFY_SCHEMA_SQL_PATH`
(req), `VULNIFY_KEV_JSON_PATH`, `VULNIFY_NVD_API_KEY`, `VULNIFY_CACHE_DIR`
(default `~/.vulnify/cache`). See `.env.example`.

---

## Testing

```bash
uv run pytest
```

Hermetic by design — each test spins a `tempfile` SQLite DB, runs the schema,
seeds fixture rows, asserts. **No network, no real DB, no mocking library.** When
adding a provider or migration, follow the nearest existing test:

- `test_migration_backfill.py` — migration + backfill shape
- `test_nvd_bulk_merge.py` — parse+write from fixture dicts (canonical for providers)
- `test_pipeline_state.py` — watermark roundtrips + skip behaviour
- `test_mcp_tools.py` — MCP tool surface (fixture DB via `mcp_module._store = …`)

Keep fetch logic separable from parse logic so parsers test against fixtures
without hitting a URL.

---

## Gotchas / load-bearing invariants

Get these wrong and things break *silently*:

- **`set_phase_state` does not commit.** The caller owns the transaction boundary — wrap it in the same `BEGIN`/`commit` as the row writes.
- **`download_zip` has no built-in cache.** The "skip if already downloaded" guard is at the *call site* (see `cveproject.py`), not in `http.py`. `exploit_ingest.py` has its own per-source cache helper.
- **Persistence is cascade + heal, not survival.** `DeleteCveRowStep` cascades a `DELETE FROM cve` to every child row (enrichment included). Data recovers because phases *re-run* post-ingestion. Don't assume enrichment rows survive a re-ingest, and don't hold external references to their integer PKs. Full model in [PIPELINE.md](docs/PIPELINE.md#persistence-cascade--heal).
- **Exploit writes bypass `CveUpsertRegistry`** — artefacts are enrichment from external corpora, not the cvelistV5 document graph, so they're written via direct SQL.
- **The `kev` table is one-row-per-CVE** (`cve_id PRIMARY KEY`, `listed` flag). `COUNT(*) FROM kev` ≈ total CVEs, **not** the KEV count — filter `listed = 1`.
- **`reference_tag` has no `cve_id`.** Join through `reference`: `reference JOIN reference_tag ON reference_tag.reference_id = reference.id WHERE reference.cve_id = ?`.
- **The MCP store connection is writable on purpose** — it runs additive migrations + FTS5 backfill on init. `readonly.py` exists but is *not* wired into `mcp.py`.
- **`vulnify-mcp` logs to stderr**, never stdout — stdout is the MCP protocol channel.
- **The CVEProject `ZIP_URL` is a pinned, dated snapshot** — bump it (`providers/cveproject.py`) when refreshing to a newer data capture.

---

## Releases

Tag scheme: `vYYYY.MM.DD` = data snapshot; `vYYYY.MM.DD.N` = code patch on the
same data. `pyproject.toml` version follows SemVer independently. Each release
ships `vulnify.db.zst` (FTS5 pre-built), `schema.sql`, and the KEV JSON snapshot.
**GitHub caps release assets at 2 GiB** — always ship the zstd'd DB, never the raw
`.db`. See [README](README.md#releases).
