# MCP server (`vulnify-mcp`)

`vulnify.mcp` is a [FastMCP](https://modelcontextprotocol.io) server that exposes
the CVE database to AI agents (Claude Code, Claude Desktop, Cursor) over **stdio**.
Agents spawn it as a subprocess on demand and call its tools.

- **Transport:** stdio. `stdout` is the protocol channel — the server logs to
  `stderr` only, so never `print()` to stdout from tool code.
- **Connection:** the store is opened **writable on purpose** — on init it runs
  additive migrations and, against older release DBs, backfills the FTS5 index.
  WAL mode means it won't block a parallel `vulnify-gather` writer.
- **Startup:** eager — config/migration errors surface before the MCP handshake,
  and the FTS5 backfill runs up front so the first text search isn't slow.
- **Limits:** every list tool caps at 100 rows (`MCP_MAX_LIMIT`); values are
  clamped, not rejected.

---

## Setup

```bash
git clone https://github.com/mez-0/vulnify.git
cd vulnify
uv sync --extra mcp

# get a DB (release asset — see the README quick-start)
gh release download -R mez-0/vulnify --pattern vulnify.db.zst
zstd -d vulnify.db.zst -o vulnify.db

# point the server at it (absolute path)
echo "VULNIFY_SQLITE_PATH=$(pwd)/vulnify.db"        > .env
echo "VULNIFY_SCHEMA_SQL_PATH=vulnify/db/schema.sql" >> .env

# smoke test — starts, then exits clean on EOF
uv run vulnify-mcp </dev/null
```

### Wire into an agent

**Claude Code:**

```bash
claude mcp add vulnify --scope user -- uv run --directory "$(pwd)" vulnify-mcp
claude mcp list          # verify: should show ✓ connected
```

**Claude Desktop / Cursor** — add to the MCP config
(`claude_desktop_config.json` / `~/.cursor/mcp.json`):

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

MCP servers attach at **session start** — restart the agent (don't `/resume`) to
pick up the tools.

---

## Tools

All tools return JSON-serialisable dicts/lists. Timestamps are ISO strings;
unknown-date sentinels are emitted as `null` (not `0001-01-01`).

### `get_cve(cve_id) -> dict | null`

Fully hydrated CVE record: CVSS metrics, KEV listing, EPSS, exploit signals,
references, CWEs, vendors, affected products, CPE matches — plus an `artefacts`
list of concrete exploit evidence (same rows as `exploits_for`). `null` if the
CVE is unknown.

### `search_cves(...) -> list[dict]`

Structured filter, ordered `published DESC`. All params optional:

| Param | Type | Meaning |
|--|--|--|
| `vendor` | str | case-insensitive substring on vendor name |
| `product` | str | case-insensitive substring on product name |
| `cwe` | str | exact CWE id, e.g. `CWE-79` |
| `kev_only` | bool | only CISA-KEV-listed CVEs |
| `min_cvss` | float | minimum max-CVSS (any version) |
| `min_epss` | float | minimum EPSS probability (0–1) |
| `year` | int | published in this year |
| `limit` | int | 1–100 (default 20) |

Returns summary rows: `cve_id`, `title`, `summary` (≤500 chars), `published`,
`max_cvss`, `severity`, `epss_score`, `kev_listed`.

### `search_cves_text(query, limit=20) -> list[dict]`

FTS5 free-text search over title / summary / technical details, Porter-stemmed,
ordered by BM25 relevance. Bare words are AND-ed; supports quoted phrases,
`OR` / `NOT`, and `prefix*`. Same summary-row shape as `search_cves`.

### `exploits_for(cve_id) -> list[dict]`

Concrete exploit artefacts: `source` (`nuclei`/`exploitdb`/`metasploit`),
`stable_id` (template id / `EDB-<n>` / module path), `url`, `artefact_type`,
`platform`, `published_date`, `confidence`. `[]` means *none found* **or** *not
yet assessed* — use `get_cve`'s tri-state signals to tell them apart.

### `references_for(cve_id, tag=None) -> list[dict]`

Reference URLs, each with its full `tags` list. With `tag` set, returns only
references carrying that tag (e.g. `patch`, `exploit`, `vendor-advisory`).

### `list_kev(since=None, limit=50) -> list[dict]`

Recent CISA KEV entries, newest `date_added` first. `since` is an ISO date lower
bound. Returns vendor/product, name, dates, required action, description.

### `database_overview() -> dict`

Totals (CVEs, vendors, products, KEV-listed, CVEs-with-EPSS), published-date
range, and per-phase last-run timestamps from `pipeline_run`.

---

## Reading exploit signals correctly

`exploit.public_poc` and `exploit.metasploit` are **tri-state**:

| Value | Meaning |
|--|--|
| `null` | **not assessed** — the contributing source hasn't completed a run. *Not* "no exploit exists." |
| `false` | assessed, none found |
| `true` | assessed, at least one artefact exists |

`public_poc` is derived from Nuclei + Exploit-DB; `metasploit` from Metasploit
modules. For the evidence behind a `true`, read the `artefacts` list. Never treat
`null` as `false` — see the [tri-state discipline](PIPELINE.md#tri-state-exploit-signals).

---

## Troubleshooting

- **Tools don't appear** — MCP attaches at session start. Restart the agent; don't `/resume`.
- **`✗ Failed to connect`** — check the exact args with `claude mcp get vulnify`; smoke-test the spawned command verbatim: `uv run --directory /path/to/vulnify vulnify-mcp </dev/null`.
- **`uv: command not found`** in the agent — agents inherit a minimal `PATH`. Use an absolute path to `uv` in the config, or symlink it into `/usr/local/bin`.
- **`VULNIFY_SQLITE_PATH is unset`** — `.env` isn't being found. Pass an absolute `--directory` so the server resolves `.env` from the right root.
- **Tool calls return nothing** — confirm the DB has data: `sqlite3 vulnify.db "SELECT COUNT(*) FROM cve"`.
- **Logs** — the server logs to stderr; in Claude Code see `/mcp` → pick the server.
