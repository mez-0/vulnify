"""Cached upstream copies expire, and a snapshot cache knows its source.

Hermetic: only the decisions are tested — never a download. Both bugs these
guard were silent: a June exploit corpus shipped in a September release, and a
bumped ``ZIP_URL`` would have ingested whatever zip was left in ``/tmp``.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path

from vulnify.http import CACHE_MAX_AGE_SEC, cache_is_fresh, fetch_cached
from vulnify.providers.cveproject import _cache_matches


class CacheAgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "corpus.csv"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _age(self, seconds: float) -> None:
        then = time.time() - seconds
        os.utime(self.path, (then, then))

    def test_a_missing_file_is_not_fresh(self) -> None:
        self.assertFalse(cache_is_fresh(self.path))

    def test_a_new_file_is_fresh(self) -> None:
        self.path.write_text("x")
        self.assertTrue(cache_is_fresh(self.path))

    def test_a_day_old_file_is_stale(self) -> None:
        self.path.write_text("x")
        self._age(CACHE_MAX_AGE_SEC + 60)
        self.assertFalse(cache_is_fresh(self.path))

    def test_a_fresh_file_is_reused_without_a_download(self) -> None:
        """An unroutable URL proves no fetch was attempted."""
        self.path.write_text("x")
        got = asyncio.run(fetch_cached("http://0.0.0.0:9/never", self.path))
        self.assertEqual(got, self.path)


class SnapshotSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.marker = Path(self.tmp.name) / ".source_url"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_a_copy_of_unknown_origin_is_not_reused(self) -> None:
        self.assertFalse(_cache_matches(self.marker, "https://example/new.zip"))

    def test_the_same_snapshot_is_reused(self) -> None:
        self.marker.write_text("https://example/new.zip\n")
        self.assertTrue(_cache_matches(self.marker, "https://example/new.zip"))

    def test_a_bumped_pin_invalidates_the_cache(self) -> None:
        self.marker.write_text("https://example/old.zip")
        self.assertFalse(_cache_matches(self.marker, "https://example/new.zip"))


if __name__ == "__main__":
    unittest.main()
