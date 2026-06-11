"""Load ``.env`` from the project root and expose required paths."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(_PROJECT_ROOT / ".env", override=False)

VULNIFY_SCHEMA_SQL_PATH = "VULNIFY_SCHEMA_SQL_PATH"
VULNIFY_SQLITE_PATH = "VULNIFY_SQLITE_PATH"
VULNIFY_KEV_JSON_PATH = "VULNIFY_KEV_JSON_PATH"
VULNIFY_NVD_API_KEY = "VULNIFY_NVD_API_KEY"
VULNIFY_CACHE_DIR = "VULNIFY_CACHE_DIR"

_DEFAULT_KEV_FILENAME = "known_exploited_vulnerabilities.json"


def get_sqlite_path_from_env() -> Path | None:
    """
    Optional SQLite DB file from ``VULNIFY_SQLITE_PATH``.

    Empty or unset means callers should use print-only ingestion. Non-empty
    values are resolved relative to the project root when not absolute.
    """
    raw = os.environ.get(VULNIFY_SQLITE_PATH, "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = _PROJECT_ROOT / path
    return path.resolve()


def get_nvd_api_key() -> str | None:
    """Optional key for api.nvd.nist.gov-style auth (raises NVD rate limits).

    Stored in ``apiKey`` request header when set.
    """
    raw = os.environ.get(VULNIFY_NVD_API_KEY, "").strip()
    return raw or None


def get_kev_catalog_path() -> Path | None:
    """
    CISA KEV JSON: ``VULNIFY_KEV_JSON_PATH`` (resolved from project root if relative),
    else ``known_exploited_vulnerabilities.json`` at repo root when that file exists.
    """
    raw = os.environ.get(VULNIFY_KEV_JSON_PATH, "").strip()
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            path = _PROJECT_ROOT / path
        path = path.resolve()
        return path if path.is_file() else None
    default = _PROJECT_ROOT / _DEFAULT_KEV_FILENAME
    return default if default.is_file() else None


def get_cache_dir() -> Path:
    """
    Local cache root for fetched exploit corpora (Nuclei / Exploit-DB / MSF).

    ``VULNIFY_CACHE_DIR`` overrides the location (handy for tests pointing at a
    tmp dir); otherwise defaults to ``~/.vulnify/cache``. Returns the resolved
    path without creating it — the download helper makes parent dirs on write.
    """
    raw = os.environ.get(VULNIFY_CACHE_DIR, "").strip()
    root = Path(raw) if raw else Path.home() / ".vulnify" / "cache"
    return root.expanduser()


def get_schema_sql_path() -> Path:
    """
    Resolve the CVE SQLite DDL file from the environment.

    Requires ``VULNIFY_SCHEMA_SQL_PATH`` (set in ``.env`` or the process
    environment). Relative paths are resolved against the project root.
    """

    raw = os.environ.get(VULNIFY_SCHEMA_SQL_PATH, "").strip()

    if not raw:
        msg = (
            f"Missing required environment variable {VULNIFY_SCHEMA_SQL_PATH}. "
            f"Set it in {_PROJECT_ROOT / '.env'} (see .env.example)."
        )

        raise RuntimeError(msg)

    path = Path(raw)

    if not path.is_absolute():
        path = _PROJECT_ROOT / path

    path = path.resolve()

    if not path.is_file():
        msg = (
            f"SQLite schema file not found: {path} "
            f"(from {VULNIFY_SCHEMA_SQL_PATH}={raw!r})"
        )

        raise FileNotFoundError(msg)

    return path
