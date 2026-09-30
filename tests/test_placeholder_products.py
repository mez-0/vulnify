"""Product identity recovered from CPE for CVEs whose CNA wrote a placeholder.

Hermetic: temp DB, the real ``schema.sql``, hand-seeded rows. Per the repo's own
rule, the scale-shaped half of this is checked separately against the real
corpus — the placeholder product is shared by six figures of CVEs and that is
exactly the shape a hermetic fixture cannot show.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest

from vulnify.db.placeholder_products import (
    PLACEHOLDER_PRODUCT_NAMES,
    _parse_cpe,
    resolve_placeholder_products,
)

SCHEMA = os.environ.get(
    "VULNIFY_SCHEMA_SQL_PATH",
    os.path.join(os.path.dirname(__file__), "..", "vulnify", "db", "schema.sql"),
)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.conn = sqlite3.connect(self.tmp.name)
        with open(SCHEMA) as fh:
            self.conn.executescript(fh.read())
        self.cur = self.conn.cursor()

    def tearDown(self):
        self.conn.close()
        os.unlink(self.tmp.name)

    def seed(self, cve_id, product_name, vendor_name, cpes):
        """One CVE on a product, with its CPE evidence."""
        self.cur.execute(
            "INSERT OR IGNORE INTO vendor (name) VALUES (?)", (vendor_name,))
        self.cur.execute(
            "SELECT vendor_id FROM vendor WHERE lower(trim(name)) = ?",
            (vendor_name.lower(),))
        vid = self.cur.fetchone()[0]
        self.cur.execute(
            "INSERT OR IGNORE INTO product (name, vendor_id) VALUES (?, ?)",
            (product_name, vid))
        self.cur.execute(
            "SELECT product_id FROM product WHERE vendor_id = ? AND name = ?",
            (vid, product_name))
        pid = self.cur.fetchone()[0]
        self.cur.execute("INSERT OR IGNORE INTO cve (cve_id) VALUES (?)", (cve_id,))
        self.cur.execute(
            "INSERT INTO affected_product (cve_id, product_id) VALUES (?, ?)",
            (cve_id, pid))
        for c in cpes:
            self.cur.execute(
                "INSERT INTO cpe_match (cve_id, criteria) VALUES (?, ?)", (cve_id, c))
        self.conn.commit()
        return pid

    def product_of(self, cve_id):
        self.cur.execute(
            "SELECT p.name, v.name FROM affected_product ap "
            "JOIN product p ON p.product_id = ap.product_id "
            "JOIN vendor v ON v.vendor_id = p.vendor_id WHERE ap.cve_id = ?",
            (cve_id,))
        return self.cur.fetchall()


class TestResolution(_Base):
    def test_a_placeholder_is_repointed_onto_its_cpe_identity(self):
        self.seed("CVE-2024-0001", "n/a", "",
                  ["cpe:2.3:a:examplecorp:exampleapp:*:*:*:*:*:*:*:*"])
        moved, cves = resolve_placeholder_products(self.conn)
        self.assertEqual((moved, cves), (1, 1))
        self.assertEqual(self.product_of("CVE-2024-0001"),
                         [("exampleapp", "examplecorp")])

    def test_a_real_product_is_left_alone(self):
        """🚨 The dangerous direction — this rewrites identity in place."""
        self.seed("CVE-2024-0002", "RealProduct", "RealVendor",
                  ["cpe:2.3:a:othervendor:otherproduct:*:*:*:*:*:*:*:*"])
        resolve_placeholder_products(self.conn)
        self.assertEqual(self.product_of("CVE-2024-0002"),
                         [("RealProduct", "RealVendor")])

    def test_ambiguous_cpes_are_left_on_the_placeholder(self):
        """A multi-product advisory must not be attached to one of them.

        Picking the most frequent slug would hide the CVE from a search for
        every other product it affects.
        """
        self.seed("CVE-2024-0003", "n/a", "", [
            "cpe:2.3:a:examplecorp:appone:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:examplecorp:apptwo:*:*:*:*:*:*:*:*",
        ])
        moved, _ = resolve_placeholder_products(self.conn)
        self.assertEqual(moved, 0)
        self.assertEqual(self.product_of("CVE-2024-0003"), [("n/a", "")])

    def test_degenerate_cpes_resolve_nothing(self):
        self.seed("CVE-2024-0004", "n/a", "",
                  ["cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"])
        self.assertEqual(resolve_placeholder_products(self.conn), (0, 0))
        self.assertEqual(self.product_of("CVE-2024-0004"), [("n/a", "")])

    def test_a_cve_with_no_cpe_rows_is_left_alone(self):
        self.seed("CVE-2024-0005", "n/a", "", [])
        self.assertEqual(resolve_placeholder_products(self.conn), (0, 0))

    def test_idempotent(self):
        """Runs on every gather, so a second pass must be a no-op."""
        self.seed("CVE-2024-0006", "n/a", "",
                  ["cpe:2.3:a:examplecorp:exampleapp:*:*:*:*:*:*:*:*"])
        first = resolve_placeholder_products(self.conn)
        second = resolve_placeholder_products(self.conn)
        self.assertEqual(first, (1, 1))
        self.assertEqual(second, (0, 0))
        self.assertEqual(self.product_of("CVE-2024-0006"),
                         [("exampleapp", "examplecorp")])

    def test_two_cves_sharing_an_identity_reuse_one_product_row(self):
        for n in ("CVE-2024-0007", "CVE-2024-0008"):
            self.seed(n, "n/a", "", ["cpe:2.3:a:examplecorp:exampleapp:*:*:*:*:*:*:*:*"])
        resolve_placeholder_products(self.conn)
        self.cur.execute("SELECT count(*) FROM product WHERE name = 'exampleapp'")
        self.assertEqual(self.cur.fetchone()[0], 1)

    def test_the_repointed_product_is_reachable_by_a_like_lookup(self):
        """The whole point: the CVE becomes findable by product name."""
        self.seed("CVE-2024-0009", "n/a", "",
                  ["cpe:2.3:a:examplecorp:exampleapp:*:*:*:*:*:*:*:*"])
        sql = ("SELECT count(*) FROM cve c "
               "JOIN affected_product ap ON ap.cve_id = c.cve_id "
               "JOIN product p ON p.product_id = ap.product_id "
               "WHERE lower(p.name) LIKE ?")
        self.cur.execute(sql, ("%exampleapp%",))
        self.assertEqual(self.cur.fetchone()[0], 0, "reachable before the fix?")
        resolve_placeholder_products(self.conn)
        self.cur.execute(sql, ("%exampleapp%",))
        self.assertEqual(self.cur.fetchone()[0], 1)


class TestIdentityMatching(_Base):
    """A CPE slug is a second spelling of a name the corpus usually has."""

    def test_a_slug_is_stored_as_the_phrase_people_type(self):
        self.seed("CVE-2024-0101", "n/a", "",
                  ["cpe:2.3:a:palo_alto_networks:pan_os:*:*:*:*:*:*:*:*"])
        resolve_placeholder_products(self.conn)
        self.assertEqual(self.product_of("CVE-2024-0101"),
                         [("pan os", "palo alto networks")])

    def test_a_respelled_vendor_reuses_the_existing_row(self):
        """``hitachivantara`` must land on ``Hitachi Vantara``, not split it."""
        self.seed("CVE-2024-0102", "Pentaho", "Hitachi Vantara", [])
        self.seed("CVE-2024-0103", "n/a", "",
                  ["cpe:2.3:a:hitachivantara:pentaho:*:*:*:*:*:*:*:*"])
        resolve_placeholder_products(self.conn)
        self.assertEqual(self.product_of("CVE-2024-0103"),
                         [("Pentaho", "Hitachi Vantara")])
        self.cur.execute("SELECT count(*) FROM vendor WHERE name LIKE '%vantara%'")
        self.assertEqual(self.cur.fetchone()[0], 1)

    def test_an_ambiguous_respelling_matches_nothing_by_key(self):
        """Two rows share the key, so the key picks neither."""
        self.seed("CVE-2024-0104", "One", "arisoft", [])
        self.seed("CVE-2024-0105", "Two", "ARI Soft", [])
        self.seed("CVE-2024-0106", "n/a", "",
                  ["cpe:2.3:a:ari-soft:three:*:*:*:*:*:*:*:*"])
        resolve_placeholder_products(self.conn)
        self.assertEqual(self.product_of("CVE-2024-0106"), [("three", "ari-soft")])

    def test_cpe_quoting_is_removed(self):
        self.seed("CVE-2024-0107", "n/a", "",
                  [r"cpe:2.3:a:fastream:ftp\+\+_server:*:*:*:*:*:*:*:*"])
        resolve_placeholder_products(self.conn)
        self.assertEqual(self.product_of("CVE-2024-0107"),
                         [("ftp++ server", "fastream")])


class TestCpeParsing(unittest.TestCase):
    def test_an_escaped_colon_does_not_shift_the_components(self):
        self.assertEqual(
            _parse_cpe(r"cpe:2.3:a:foo\:bar:baz:1.0:*:*:*:*:*:*:*"),
            ("foo:bar", "baz"))

    def test_well_formed(self):
        self.assertEqual(
            _parse_cpe("cpe:2.3:a:examplecorp:exampleapp:1.0:*:*:*:*:*:*:*"),
            ("examplecorp", "exampleapp"))

    def test_rejects_wildcards_and_junk(self):
        for c in ("cpe:2.3:a:*:app:*:*:*:*:*:*:*:*",
                  "cpe:2.3:a:vendor:-:*:*:*:*:*:*:*:*",
                  "cpe:2.2:a:vendor:app", "not-a-cpe", ""):
            self.assertIsNone(_parse_cpe(c), c)

    def test_the_placeholder_set_matches_the_ingest_filter(self):
        """The asymmetry between the two is the bug; keep them aligned."""
        for word in ("n/a", "unknown", "none"):
            self.assertIn(word, PLACEHOLDER_PRODUCT_NAMES)


if __name__ == "__main__":
    unittest.main()
