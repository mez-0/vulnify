"""Tests for the pipeline_run watermark + cron-safe phase behaviour."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vulnify.db.pipeline_state import get_phase_state, set_phase_state
from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.providers.cisa_kev import KEV_PIPELINE_PHASE, ingest_cisa_kev_catalog
from vulnify.providers.enrichment import _split_last_mod_windows


class PipelineStateTests(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(
            repo_root / "vulnify" / "db" / "schema.sql"
        )
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp.name)
        tmp.close()

    def tearDown(self) -> None:
        self.db_path.unlink(missing_ok=True)

    def test_get_returns_none_for_unknown_phase(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            completed, watermark = get_phase_state(store.connection, "ghosts")
        self.assertIsNone(completed)
        self.assertIsNone(watermark)

    def test_set_and_get_roundtrip(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            set_phase_state(
                store.connection,
                "nvd_bulk",
                completed_at="2026-05-01T00:00:00+00:00",
                watermark="2026-05-01T00:00:00+00:00",
            )
            store.connection.commit()
            completed, watermark = get_phase_state(store.connection, "nvd_bulk")
        self.assertEqual(completed, "2026-05-01T00:00:00+00:00")
        self.assertEqual(watermark, "2026-05-01T00:00:00+00:00")

    def test_set_overwrites_existing_state(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            set_phase_state(
                store.connection,
                "kev",
                completed_at="2026-01-01T00:00:00+00:00",
                watermark="2026.01.01",
            )
            set_phase_state(
                store.connection,
                "kev",
                completed_at="2026-05-01T00:00:00+00:00",
                watermark="2026.05.01",
            )
            store.connection.commit()
            _, watermark = get_phase_state(store.connection, "kev")
        self.assertEqual(watermark, "2026.05.01")


class NvdWindowSplitTests(unittest.TestCase):
    def test_empty_window_when_start_at_or_after_end(self) -> None:
        same = "2026-05-01T00:00:00+00:00"
        self.assertEqual(_split_last_mod_windows(same, same), [])
        self.assertEqual(
            _split_last_mod_windows(
                "2026-05-02T00:00:00+00:00", "2026-05-01T00:00:00+00:00"
            ),
            [],
        )

    def test_single_window_when_under_120_days(self) -> None:
        windows = _split_last_mod_windows(
            "2026-04-01T00:00:00+00:00", "2026-05-01T00:00:00+00:00"
        )
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0][0], "2026-04-01T00:00:00+00:00")
        self.assertEqual(windows[0][1], "2026-05-01T00:00:00+00:00")

    def test_splits_into_multiple_when_over_120_days(self) -> None:
        # 365-day span needs at least four 119-day chunks.
        start = datetime(2025, 5, 1, tzinfo=timezone.utc)
        end = start + timedelta(days=365)
        windows = _split_last_mod_windows(
            start.isoformat(timespec="seconds"),
            end.isoformat(timespec="seconds"),
        )
        self.assertGreaterEqual(len(windows), 4)
        # Boundaries chain head-to-tail and end at exactly ``end``.
        for prev, nxt in zip(windows, windows[1:]):
            self.assertEqual(prev[1], nxt[0])
        self.assertEqual(windows[-1][1], end.isoformat(timespec="seconds"))


class KevCatalogVersionSkipTests(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(
            repo_root / "vulnify" / "db" / "schema.sql"
        )
        tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp_db.name)
        tmp_db.close()
        tmp_kev = tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        )
        json.dump(
            {
                "catalogVersion": "2026.05.01",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-KEV1",
                        "vendorProject": "Acme",
                        "product": "Widget",
                        "vulnerabilityName": "Test KEV entry",
                        "shortDescription": "test",
                        "dateAdded": "2026-05-01",
                        "dueDate": "2026-05-15",
                        "knownRansomwareCampaignUse": "Unknown",
                        "notes": "",
                        "cwes": ["CWE-79"],
                    }
                ],
            },
            tmp_kev,
        )
        tmp_kev.close()
        self.kev_path = Path(tmp_kev.name)

    def tearDown(self) -> None:
        self.db_path.unlink(missing_ok=True)
        self.kev_path.unlink(missing_ok=True)

    def test_second_run_skips_when_catalog_version_unchanged(self) -> None:
        import asyncio

        with SqliteCveStore(self.db_path) as store:
            first = asyncio.run(
                ingest_cisa_kev_catalog(store, catalog_path=self.kev_path)
            )
            self.assertEqual(first, 1)
            _, version = get_phase_state(store.connection, KEV_PIPELINE_PHASE)
            self.assertEqual(version, "2026.05.01")
            second = asyncio.run(
                ingest_cisa_kev_catalog(store, catalog_path=self.kev_path)
            )
        self.assertEqual(second, 0)


if __name__ == "__main__":
    unittest.main()
