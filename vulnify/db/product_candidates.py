"""Product candidates named in a CVE's own description, for CVEs nothing else identifies.

**What it is for.** After the ``placeholder_products`` phase, a CVE still anchored
only on the placeholder product has no structured identity at all: the CNA wrote
``n/a`` and NVD holds no vulnerable CPE (backlog or ``Deferred``). About 4,100
CVEs on the 2026-11-02 build, nearly all published 2024–2026. The only
evidence left is prose.

🚨 **A candidate, never a fact — which is why it is its own table.** Rows here
are not written to ``affected_product``, which every consumer (``search_cves``,
the explorer, any downstream product join) reads as what the CVE affects. A consumer
gets a candidate only by asking for ``product_candidate`` by name.

**The match, and why it is this narrow.** Measured on the 2026-11-02 build by
running the matcher blind over the 40,643 placeholder CVEs that *do* have
vulnerable CPEs, and scoring each link by whether its vendor is one the CPEs
name:

==========================================================  ==================
Rule                                                        Links, wrong vendor
==========================================================  ==================
any known product named anywhere in the text                96%
… and its vendor also named anywhere                        39%
… vendor name immediately followed by one of its products   44%
… and excluding self-named pairs (``file``/``file``)        **7%**
==========================================================  ==================

The 7% is an upper bound — ``Zoho ManageEngine`` scores as wrong against the
CPE slug ``zohocorp``. The self-named exclusion is what does the work: CNA
garbage like ``unspecified``/``unspecified``, ``root``/``root``,
``session``/``session`` matches ordinary English, and platform names like
``WordPress``/``WordPress`` appear in every plugin CVE without being its product.

⚠️ **It cannot rescue every CVE, and must not try.** A CVE that names only the
product, say ``Relay3``, gets **no** candidate when the only ``Relay`` in the
corpus is another vendor's WordPress theme and the CVE's own vendor is named
nowhere but a reference URL. Linking it would be a confident wrong answer. Full
text search (``cve_fts``) is the honest route for those.
"""

from __future__ import annotations

import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass

from loguru import logger

from vulnify.db.placeholder_products import placeholder_product_ids

#: A vendor or product name shorter than this (punctuation stripped) is too
#: likely to be an ordinary word or an abbreviation of something else.
MIN_NAME_CHARS = 3

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]*")
_NON_ALNUM = re.compile(r"[^a-z0-9]")
#: What may trail a product's last token and still be that product:
#: ``Relay3`` is Relay, ``DIR-882`` after ``DIR`` is a model of it. Letters may
#: not — ``Discover`` is not ``Disc``.
_VERSION_TAIL = re.compile(r"^[0-9.]*$")


def _norm(text: str) -> str:
    return _NON_ALNUM.sub("", text.lower())


@dataclass(frozen=True, slots=True)
class _Token:
    norm: str
    start: int
    end: int


def _tokens(text: str) -> list[_Token]:
    return [
        _Token(n, m.start(), m.end())
        for m in _TOKEN.finditer(text)
        if (n := _norm(m.group()))
    ]


def _name_tokens(name: str) -> tuple[str, ...]:
    return tuple(t.norm for t in _tokens(name))


class _Dictionary:
    """Known vendors by first token, and each vendor's matchable products."""

    def __init__(self, cur: sqlite3.Cursor, placeholders: list[int]) -> None:
        self.vendors: dict[str, list[tuple[int, tuple[str, ...]]]] = defaultdict(list)
        vendor_norm: dict[int, str] = {}
        cur.execute("SELECT vendor_id, name FROM vendor WHERE trim(name) <> ''")
        for vid, name in cur.fetchall():
            toks = _name_tokens(name)
            if toks and len("".join(toks)) >= MIN_NAME_CHARS:
                self.vendors[toks[0]].append((vid, toks))
                vendor_norm[vid] = "".join(toks)

        self.products: dict[int, list[tuple[int, tuple[str, ...]]]] = defaultdict(list)
        excluded = set(placeholders)
        cur.execute("SELECT product_id, vendor_id, name FROM product")
        for pid, vid, name in cur.fetchall():
            if pid in excluded or vid not in vendor_norm:
                continue
            toks = _name_tokens(name)
            joined = "".join(toks)
            # Self-named pairs are CNA noise or platform names — see module doc.
            if len(joined) < MIN_NAME_CHARS or joined == vendor_norm[vid]:
                continue
            self.products[vid].append((pid, toks))


def _matches_at(text: list[_Token], at: int, name: tuple[str, ...]) -> bool:
    seg = text[at:at + len(name)]
    if len(seg) != len(name):
        return False
    if any(a.norm != b for a, b in zip(seg[:-1], name[:-1])):
        return False
    last, want = seg[-1].norm, name[-1]
    return last == want or (last.startswith(want) and bool(_VERSION_TAIL.match(last[len(want):])))


def find_candidates(text: str, dictionary: _Dictionary) -> dict[int, str]:
    """Products a description names as ``<vendor> <product>``.

    :returns: ``{product_id: matched span of text}``.
    """
    toks = _tokens(text)
    found: dict[int, str] = {}
    for i, tok in enumerate(toks):
        for vid, vname in dictionary.vendors.get(tok.norm, ()):
            if tuple(t.norm for t in toks[i:i + len(vname)]) != vname:
                continue
            after = i + len(vname)
            for pid, pname in dictionary.products.get(vid, ()):
                # Directly after the vendor ("D-Link DIR-882"), or a product
                # name that itself begins with the vendor ("Cisco IOS" under Cisco).
                for start in (after, i) if pname[:len(vname)] == vname else (after,):
                    if _matches_at(toks, start, pname):
                        found.setdefault(pid, text[toks[i].start:toks[start + len(pname) - 1].end])
                        break
    return found


def rebuild_product_candidates(conn: sqlite3.Connection) -> tuple[int, int]:
    """Replace ``product_candidate`` for every CVE still placeholder-only.

    Wholesale: the table is derived, and ``affected_product`` is cascade-wiped
    and rebuilt on re-ingest, so which CVEs are still unidentified changes
    every gather.

    :param conn: Open connection to the corpus.
    :returns: ``(rows_written, cves_with_a_candidate)``.
    """
    cur = conn.cursor()
    cur.execute("DELETE FROM product_candidate")
    placeholders = placeholder_product_ids(cur)
    if not placeholders:
        return 0, 0
    marks = ",".join("?" * len(placeholders))
    cur.execute(
        f"""
        SELECT c.cve_id, coalesce(c.title, ''), coalesce(c.summary, '')
        FROM cve c
        WHERE c.cve_id IN (
                SELECT cve_id FROM affected_product WHERE product_id IN ({marks})
                EXCEPT
                SELECT cve_id FROM affected_product WHERE product_id NOT IN ({marks}))
        """,
        (*placeholders, *placeholders),
    )
    targets = cur.fetchall()
    dictionary = _Dictionary(cur, placeholders)

    rows: list[tuple[str, int, str]] = []
    for cve_id, title, summary in targets:
        found = find_candidates(f"{title}\n{summary}", dictionary)
        rows.extend((cve_id, pid, span) for pid, span in found.items())
    cur.executemany(
        "INSERT INTO product_candidate (cve_id, product_id, matched_text) VALUES (?, ?, ?)",
        rows,
    )
    cves = len({r[0] for r in rows})
    logger.info(
        "product candidates: {} rows across {} of {} unidentified CVEs",
        len(rows), cves, len(targets),
    )
    return len(rows), cves


__all__ = ["MIN_NAME_CHARS", "find_candidates", "rebuild_product_candidates"]
