"""Read-only SQLite connection helper, shared by the explore app and the MCP server."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def connect_readonly(db_path: str | Path) -> sqlite3.Connection:
    """Open SQLite in read-only mode (no write locks on ingestion)."""

    resolved = Path(db_path).expanduser().resolve()
    uri = f"file:{resolved.as_posix()}?mode=ro"
    return sqlite3.connect(uri, uri=True, detect_types=sqlite3.PARSE_DECLTYPES)


__all__ = ["connect_readonly"]
