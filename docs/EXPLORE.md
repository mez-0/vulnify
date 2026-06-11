# Explorer (Streamlit)

`explore/app.py` is a Streamlit dashboard over the vulnify DB — roughly 70
pre-built views for eyeballing the corpus without writing SQL. It's the
human-facing counterpart to the [MCP server](MCP.md): same database, different
consumer.

```bash
uv sync --extra explore
uv run streamlit run explore/app.py
```

Opens on `http://localhost:8501`. It reads the DB at `VULNIFY_SQLITE_PATH` (from
`.env`) — the same DB the pipeline builds and the MCP server serves.

---

## Layout

**Sidebar:**

- **Data source** — switch between DBs (e.g. compare two release snapshots side
  by side).
- **Filters** — a published-date window applied across the views.

**Views are grouped into 14 tabs:**

| Tab | What's in it |
|--|--|
| **Overview** | Enrichment coverage (which CVEs have CVSS / EPSS / KEV / exploit data), headline totals |
| **Vendors** | Assigner organisations, vendor CVE load, primary-vs-affected roles |
| **Trends** | Publication volume over time — severity-stacked, year-over-year overlay, weekly granularity |
| **Vendor links** | Strongest vendor co-occurrence pairs, co-occurrence heatmap, interactive vendor graph |
| **Severity & CWE** | Severity distribution (max CVSS per CVE), CVSS-vs-year, exploitability-vs-impact subscores, CWE breakdowns |
| **Enrichment** | Coverage/density of each enrichment source |
| **Exploit landscape** | Exploit artefacts by source, exploit-maturity distribution, exploited-in-the-wild trends |
| **KEV deep dive** | CISA KEV listings by month-added, listing lag, ransomware flag |
| **CVSS vector** | Attack-vector / complexity / privilege breakdowns from decomposed CVSS metrics |
| **Products & CPEs** | Product pressure, CPE applicability coverage |
| **References** | Reference volume, trust, and tag distribution |
| **Threat intel** | EPSS distribution, EPSS vs CVSS, EPSS by severity, percentile density, KEV share by EPSS decile |
| **Lifecycle** | Publication recency, modification lag, CVE state transitions |
| **Pipeline health** | Per-phase last-run times and coverage — a quick "is the data fresh?" check |

---

## How it's wired

Queries are split across two modules; `app.py` is presentation only:

- **`explore/data.py`** — overview / landing queries (~20 functions).
- **`explore/data_views.py`** — the bulk of the per-chart queries (~49 functions).

Every view is a plain function returning a DataFrame; `app.py` calls it and hands
the result to Plotly. Query results are cached per DB + filter window.

**To add a view:** write a query function in `data_views.py` (or `data.py`), then
wire it into the relevant tab in `app.py` with a chart call. Keep SQL in the data
modules — don't inline it in `app.py`.

> The explorer is read-only in spirit but opens the store the same way the MCP
> server does. Run it against a copy if a `vulnify-gather` is writing
> concurrently — WAL mode allows it, but you'll see partial data mid-refresh.
