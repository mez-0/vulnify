"""EPSS fetch failures: retried, never destructive, never silent.

FIRST's API returns 502/504 in bursts. Before retries were wired in, a single
bad response dropped a whole batch and the phase still reported success. The
fetcher is injected so these paths run without a network.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from loguru import logger

from vulnify.db.sqlite_store import SqliteCveStore
from vulnify.models.cve import CVE
from vulnify.providers import epss


def _ids_in(url: str) -> list[str]:
    return parse_qs(urlparse(url).query)["cve"][0].split(",")


class FakeFirst:
    """Answers like FIRST, failing the first ``fail_times`` requests per batch."""

    def __init__(self, scores: dict[str, float], *, fail_times: int = 0) -> None:
        self.scores = scores
        self.fail_times = fail_times
        self.calls: dict[str, int] = {}

    async def __call__(self, url: str):
        ids = _ids_in(url)
        key = ids[0]
        self.calls[key] = self.calls.get(key, 0) + 1
        if self.calls[key] <= self.fail_times:
            return {}, "HTTP 502"
        rows = [
            {"cve": c, "epss": str(self.scores[c]), "percentile": "0.5"}
            for c in ids
            if c in self.scores
        ]
        return {"status": "OK", "data": rows}, None


class EpssFetchTests(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        os.environ["VULNIFY_SCHEMA_SQL_PATH"] = str(
            repo_root / "vulnify" / "db" / "schema.sql"
        )
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(tmp.name)
        tmp.close()
        self.warnings: list[str] = []
        self._sink = logger.add(
            lambda m: self.warnings.append(str(m)), level="WARNING"
        )

    def tearDown(self) -> None:
        logger.remove(self._sink)
        self.db_path.unlink(missing_ok=True)

    def _score(self, store: SqliteCveStore, cve_id: str):
        return store.connection.execute(
            "SELECT epss_score FROM intel WHERE cve_id = ?", (cve_id,)
        ).fetchone()[0]

    def _seed(self, store: SqliteCveStore, ids: list[str]) -> None:
        for cid in ids:
            store.upsert_cve(CVE(cve_id=cid))

    def test_a_transient_failure_is_healed_by_the_deferred_pass(self) -> None:
        ids = ["CVE-2026-0001", "CVE-2026-0002"]
        fake = FakeFirst({c: 0.3 for c in ids}, fail_times=1)
        with SqliteCveStore(self.db_path) as store:
            self._seed(store, ids)
            updated = asyncio.run(epss.enrich_all_epss(store, fetch=fake))
            self.assertEqual(updated, 2)
            self.assertEqual([self._score(store, c) for c in ids], [0.3, 0.3])
        self.assertEqual(self.warnings[1:], [], "only the per-batch warning")

    def test_a_persistent_failure_keeps_old_scores_and_says_so(self) -> None:
        with SqliteCveStore(self.db_path) as store:
            self._seed(store, ["CVE-2026-0003", "CVE-2026-0004"])
            store.connection.execute(
                "UPDATE intel SET epss_score = 0.42, epss_percentile = 0.9 "
                "WHERE cve_id = 'CVE-2026-0003'"
            )
            store.connection.commit()
            fake = FakeFirst({}, fail_times=99)
            updated = asyncio.run(epss.enrich_all_epss(store, fetch=fake))
            self.assertEqual(updated, 0)
            self.assertEqual(self._score(store, "CVE-2026-0003"), 0.42)
            self.assertIsNone(self._score(store, "CVE-2026-0004"))
        self.assertTrue(
            any("still failing" in w for w in self.warnings),
            "a residual failure must be reported, not just logged per batch",
        )

    def test_failures_are_retried_per_batch_not_per_run(self) -> None:
        ids = [f"CVE-2026-{i:04d}" for i in range(1, 251)]  # 3 batches
        fake = FakeFirst({c: 0.1 for c in ids}, fail_times=1)
        with SqliteCveStore(self.db_path) as store:
            self._seed(store, ids)
            asyncio.run(epss.enrich_all_epss(store, fetch=fake))
        self.assertEqual(sorted(fake.calls.values()), [2, 2, 2])

    def test_a_row_without_a_score_stays_null(self) -> None:
        async def scoreless(url: str):
            return {"data": [{"cve": "CVE-2026-0005", "epss": None,
                              "percentile": None}]}, None

        with SqliteCveStore(self.db_path) as store:
            self._seed(store, ["CVE-2026-0005"])
            n = asyncio.run(
                epss.enrich_epss_batch(store, ["CVE-2026-0005"], fetch=scoreless)
            )
            self.assertEqual(n, 0)
            self.assertIsNone(self._score(store, "CVE-2026-0005"))


if __name__ == "__main__":
    unittest.main()
