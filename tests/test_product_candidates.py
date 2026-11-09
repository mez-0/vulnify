"""Description-named product candidates for CVEs nothing structured identifies.

Hermetic: temp DB, the real ``schema.sql``, hand-seeded rows. The precision
figures in ``db/product_candidates.py`` were measured on the real corpus; what
is pinned here is each rule that measurement made load-bearing.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest

from vulnify.db.placeholder_products import resolve_placeholder_products
from vulnify.db.product_candidates import rebuild_product_candidates

SCHEMA = os.path.join(os.path.dirname(__file__), "..", "vulnify", "db", "schema.sql")


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.conn = sqlite3.connect(self.tmp.name)
        with open(SCHEMA) as fh:
            self.conn.executescript(fh.read())
        self.cur = self.conn.cursor()
        self.placeholder = self.product("n/a", "")

    def tearDown(self):
        self.conn.close()
        os.unlink(self.tmp.name)

    def product(self, name, vendor):
        self.cur.execute("INSERT OR IGNORE INTO vendor (name) VALUES (?)", (vendor,))
        self.cur.execute("SELECT vendor_id FROM vendor WHERE name = ?", (vendor,))
        vid = self.cur.fetchone()[0]
        self.cur.execute(
            "INSERT OR IGNORE INTO product (name, vendor_id) VALUES (?, ?)", (name, vid))
        self.cur.execute(
            "SELECT product_id FROM product WHERE name = ? AND vendor_id = ?", (name, vid))
        return self.cur.fetchone()[0]

    def cve(self, cve_id, summary, product_id=None, title=""):
        self.cur.execute(
            "INSERT INTO cve (cve_id, title, summary) VALUES (?, ?, ?)",
            (cve_id, title, summary))
        self.cur.execute(
            "INSERT INTO affected_product (cve_id, product_id) VALUES (?, ?)",
            (cve_id, product_id or self.placeholder))
        self.conn.commit()

    def candidates(self, cve_id):
        self.cur.execute(
            "SELECT v.name, p.name, pc.matched_text FROM product_candidate pc "
            "JOIN product p ON p.product_id = pc.product_id "
            "JOIN vendor v ON v.vendor_id = p.vendor_id WHERE pc.cve_id = ? "
            "ORDER BY p.name", (cve_id,))
        return self.cur.fetchall()


class TestMatching(_Base):
    def test_vendor_then_product_is_a_candidate(self):
        self.product("DIR-882", "D-Link")
        self.cve("CVE-2025-0001", "A buffer overflow in D-Link DIR-882 1.30 allows RCE.")
        rebuild_product_candidates(self.conn)
        self.assertEqual(self.candidates("CVE-2025-0001"),
                         [("D-Link", "DIR-882", "D-Link DIR-882")])

    def test_a_trailing_version_is_still_the_product(self):
        """``Relay3`` is Relay — when the vendor that makes it is named."""
        self.product("Relay", "Northwind")
        self.cve("CVE-2025-0002", "Path traversal in Northwind Relay3 thru 3.3.67.")
        rebuild_product_candidates(self.conn)
        self.assertEqual(self.candidates("CVE-2025-0002"),
                         [("Northwind", "Relay", "Northwind Relay3")])

    def test_a_trailing_word_is_a_different_product(self):
        """``Discover`` is not ``Disc``: only digits and dots may trail."""
        self.product("Disc", "ExampleCorp")
        self.cve("CVE-2025-0003", "ExampleCorp Discover leaks session tokens.")
        rebuild_product_candidates(self.conn)
        self.assertEqual(self.candidates("CVE-2025-0003"), [])

    def test_a_product_named_without_its_vendor_is_not_a_candidate(self):
        """🚨 A product named without its vendor, colliding with another vendor's.

        The only ``Relay`` in the corpus is acmethemes' WordPress theme, and the
        remote-desktop CVE never names acmethemes. Matching the product alone
        would attach an RCE to the wrong vendor with a straight face.
        """
        self.product("Relay", "acmethemes")
        self.cve("CVE-2025-0090",
                 "A path traversal vulnerability in Relay3 thru 3.3.67 allows an "
                 "unauthenticated attacker to read arbitrary files on the server.")
        rebuild_product_candidates(self.conn)
        self.assertEqual(self.candidates("CVE-2025-0090"), [])

    def test_vendor_and_product_must_be_adjacent(self):
        self.product("Exchange", "Microsoft")
        self.cve("CVE-2025-0004",
                 "Unlike Microsoft guidance, the mail relay forwards Exchange headers.")
        rebuild_product_candidates(self.conn)
        self.assertEqual(self.candidates("CVE-2025-0004"), [])

    def test_self_named_pairs_are_ignored(self):
        """``file``/``file``, ``WordPress``/``WordPress``: noise or a platform."""
        self.product("WordPress", "WordPress")
        self.product("file", "file")
        self.cve("CVE-2025-0005",
                 "The Foo plugin for WordPress WordPress allows file file upload.")
        rebuild_product_candidates(self.conn)
        self.assertEqual(self.candidates("CVE-2025-0005"), [])

    def test_a_product_name_that_begins_with_its_vendor(self):
        self.product("Cisco IOS XE", "Cisco")
        self.cve("CVE-2025-0006", "Cisco IOS XE 17.9 web UI privilege escalation.")
        rebuild_product_candidates(self.conn)
        self.assertEqual(self.candidates("CVE-2025-0006"),
                         [("Cisco", "Cisco IOS XE", "Cisco IOS XE")])

    def test_the_title_is_searched_too(self):
        self.product("DIR-882", "D-Link")
        self.cve("CVE-2025-0007", "Stack overflow in the httpd binary.",
                 title="D-Link DIR-882 httpd overflow")
        rebuild_product_candidates(self.conn)
        self.assertEqual(len(self.candidates("CVE-2025-0007")), 1)


class TestScope(_Base):
    def test_a_cve_with_a_named_product_gets_no_candidates(self):
        """Candidates exist only where nothing structured does."""
        real = self.product("DIR-882", "D-Link")
        self.cve("CVE-2025-0101", "D-Link DIR-882 overflow.", product_id=real)
        rebuild_product_candidates(self.conn)
        self.assertEqual(self.candidates("CVE-2025-0101"), [])

    def test_a_cve_resolved_from_cpe_gets_no_candidates(self):
        self.product("DIR-882", "D-Link")
        self.cve("CVE-2025-0102", "D-Link DIR-882 overflow.")
        self.cur.execute(
            "INSERT INTO cpe_match (cve_id, criteria) VALUES (?, ?)",
            ("CVE-2025-0102", "cpe:2.3:o:dlink:dir-882_firmware:*:*:*:*:*:*:*:*"))
        resolve_placeholder_products(self.conn)
        rebuild_product_candidates(self.conn)
        self.assertEqual(self.candidates("CVE-2025-0102"), [])

    def test_rebuild_is_wholesale(self):
        """A CVE identified since the last run loses its stale candidate."""
        self.product("DIR-882", "D-Link")
        self.cve("CVE-2025-0103", "D-Link DIR-882 overflow.")
        self.assertEqual(rebuild_product_candidates(self.conn), (1, 1))
        self.assertEqual(rebuild_product_candidates(self.conn), (1, 1))
        self.cur.execute(
            "UPDATE affected_product SET product_id = ? WHERE cve_id = 'CVE-2025-0103'",
            (self.product("DIR-882", "D-Link"),))
        self.assertEqual(rebuild_product_candidates(self.conn), (0, 0))
        self.assertEqual(self.candidates("CVE-2025-0103"), [])

    def test_candidates_never_reach_affected_product(self):
        self.product("DIR-882", "D-Link")
        self.cve("CVE-2025-0104", "D-Link DIR-882 overflow.")
        rebuild_product_candidates(self.conn)
        self.cur.execute(
            "SELECT count(*) FROM affected_product WHERE cve_id = 'CVE-2025-0104' "
            "AND product_id <> ?", (self.placeholder,))
        self.assertEqual(self.cur.fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
