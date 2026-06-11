"""CVE SQLite upsert as a configurable pipeline (policy + registry of steps)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from vulnify.db.sql_conversion import (
    bool_to_sql,
    bool_to_sql_nullable,
    date_to_sql,
    datetime_to_sql,
)
from vulnify.models.cve import CVE
from vulnify.models.vendor import Product, Vendor


@dataclass(frozen=True, slots=True)
class CveUpsertPolicy:
    """Per-upsert toggles — default writes the full normalized graph."""

    core_row: bool = True
    primary_vendor_edge: bool = True
    affected_products: bool = True
    affected_vendor_edges: bool = True
    cwes: bool = True
    cvss_scores: bool = True
    cpe_matches: bool = True
    exploit: bool = True
    kev: bool = True
    intel_scores: bool = True
    intel_string_lists: bool = True
    references: bool = True
    cve_tags: bool = True


@dataclass(slots=True)
class CveUpsertContext:
    """Mutable state threaded through pipeline steps."""

    cve: CVE
    policy: CveUpsertPolicy = field(default_factory=CveUpsertPolicy)
    data_version: str = ""
    data_type: str = ""
    state: str = ""
    assigner_org_id: str = ""
    primary_vendor_id: int = -1
    affected_vendor_ids: dict[int, None] = field(default_factory=dict)

    @classmethod
    def build(cls, cve: CVE, policy: CveUpsertPolicy | None = None) -> CveUpsertContext:
        """
        Build a CVE upsert context.

        :param cve: The CVE.
        :type cve: CVE
        :param policy: The policy.
        :type policy: CveUpsertPolicy | None
        :return: The CVE upsert context.
        :rtype: CveUpsertContext
        """
        ex = cve.extra
        return cls(
            cve=cve,
            policy=policy or CveUpsertPolicy(),
            data_version=ex.get("dataVersion", "") or "",
            data_type=ex.get("dataType", "") or "",
            state=ex.get("state", "") or "",
            assigner_org_id=ex.get("assignerOrgId", "") or "",
        )


@runtime_checkable
class CveUpsertSink(Protocol):
    """Port implemented by ``SqliteCveStore`` so steps stay storage-agnostic."""

    def ensure_vendor(self, cur: sqlite3.Cursor, vendor: Vendor) -> int: ...

    """
    Ensure a vendor.

    :param cur: The database cursor.
    :type cur: sqlite3.Cursor
    :param vendor: The vendor.
    :type vendor: Vendor
    :return: The vendor ID.
    :rtype: int
    """

    def ensure_product(
        self, cur: sqlite3.Cursor, product: Product, vendor_id: int
    ) -> int: ...

    def ensure_tag_id(self, cur: sqlite3.Cursor, name: str) -> int: ...


class CveUpsertStep(Protocol):
    def apply(
        self, sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class DeleteCveRowStep:
    """Cascade-delete existing graph for ``cve_id`` via FK."""

    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Delete a CVE row.

        :param _sink: The sink.
        :type _sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        cur.execute("DELETE FROM cve WHERE cve_id = ?", (ctx.cve.cve_id,))


@dataclass(frozen=True, slots=True)
class InsertCveCoreStep:
    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert a CVE core row.

        :param _sink: The sink.
        :type _sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """

        if not ctx.policy.core_row:
            return

        c = ctx.cve

        cur.execute(
            """
            INSERT INTO cve (
                cve_id, title, cna, summary, technical_details,
                published, modified, discovered,
                priority_score, confidence,
                data_version, data_type, state, assigner_org_id,
                vuln_status, source_identifier
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                c.cve_id,
                c.title or "",
                c.cna or "",
                c.summary or "",
                c.technical_details or "",
                datetime_to_sql(c.published),
                datetime_to_sql(c.modified),
                datetime_to_sql(c.discovered),
                int(c.priority_score),
                float(c.confidence),
                ctx.data_version,
                ctx.data_type,
                ctx.state,
                ctx.assigner_org_id,
                c.vuln_status or "",
                c.source_identifier or "",
            ),
        )


@dataclass(frozen=True, slots=True)
class PrimaryVendorStep:
    def apply(
        self, sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert a primary vendor edge.

        :param sink: The sink.
        :type sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """

        if not ctx.policy.primary_vendor_edge:
            return

        c = ctx.cve

        ctx.primary_vendor_id = sink.ensure_vendor(cur, c.primary_vendor)

        cur.execute(
            """
            INSERT INTO cve_vendor (cve_id, vendor_id, role)
            VALUES (?, ?, ?)
            """,
            (c.cve_id, ctx.primary_vendor_id, "primary"),
        )

        ctx.affected_vendor_ids = {ctx.primary_vendor_id: None}


@dataclass(frozen=True, slots=True)
class AffectedProductsStep:
    def apply(
        self, sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert affected products.

        :param sink: The sink.
        :type sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        if not ctx.policy.affected_products:
            return
        c = ctx.cve
        # Collapse duplicate affected_products within one CVE input. Some CNAs
        # publish the same product multiple times in cvelistV5; without this we
        # stamp out N copies + N copies of every version_range under them.
        seen_products: dict[int, tuple[int, set[tuple[str, str, str, str, str, str]]]] = {}
        for ap in c.affected_products:
            v = ap.product.vendor if ap.product.vendor else Vendor()
            vid = sink.ensure_vendor(cur, v)
            ctx.affected_vendor_ids[vid] = None
            pid = sink.ensure_product(cur, ap.product, vid)
            entry = seen_products.get(pid)
            if entry is None:
                cur.execute(
                    """
                    INSERT INTO affected_product (cve_id, product_id, affected, notes)
                    VALUES (?, ?, ?, ?)
                    """,
                    (c.cve_id, pid, bool_to_sql(ap.affected), ap.notes or ""),
                )
                ap_row_id = int(cur.lastrowid)
                entry = (ap_row_id, set())
                seen_products[pid] = entry
            ap_row_id, seen_vrs = entry
            for vr in ap.versions:
                key = (
                    vr.start_including or "",
                    vr.start_excluding or "",
                    vr.end_including or "",
                    vr.end_excluding or "",
                    vr.fixed_version or "",
                    vr.raw_text or "",
                )
                if key in seen_vrs:
                    continue
                seen_vrs.add(key)
                cur.execute(
                    """
                    INSERT INTO version_range (
                        affected_product_id,
                        start_including, start_excluding, end_including, end_excluding,
                        fixed_version, raw_text
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ap_row_id, *key),
                )


@dataclass(frozen=True, slots=True)
class AffectedVendorEdgesStep:
    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert affected vendor edges.

        :param _sink: The sink.
        :type _sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        if not ctx.policy.affected_vendor_edges:
            return
        cve_id = ctx.cve.cve_id
        primary_vid = ctx.primary_vendor_id
        for vid in ctx.affected_vendor_ids:
            if vid == primary_vid:
                continue
            cur.execute(
                """
                INSERT OR IGNORE INTO cve_vendor (cve_id, vendor_id, role)
                VALUES (?, ?, ?)
                """,
                (cve_id, vid, "affected"),
            )


@dataclass(frozen=True, slots=True)
class CweUpsertStep:
    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert CWEs.

        :param _sink: The sink.
        :type _sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        if not ctx.policy.cwes:
            return
        cve_id = ctx.cve.cve_id
        for cwe in ctx.cve.cwes:
            cid = (cwe.cwe_id or "").strip()
            if not cid:
                continue
            cur.execute(
                """
                INSERT INTO cwe (cwe_id, name, description)
                VALUES (?, ?, ?)
                ON CONFLICT(cwe_id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description
                """,
                (cid, cwe.name or "", cwe.description or ""),
            )
            cur.execute(
                "INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (?, ?)",
                (cve_id, cid),
            )


@dataclass(frozen=True, slots=True)
class CvssUpsertStep:
    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert CVSS scores.

        :param _sink: The sink.
        :type _sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        if not ctx.policy.cvss_scores:
            return
        cve_id = ctx.cve.cve_id
        for cv in ctx.cve.cvss_scores:
            cur.execute(
                """
                INSERT INTO cvss (
                    cve_id, version, score, vector, severity,
                    attack_vector, attack_complexity, privileges_required,
                    user_interaction, scope,
                    confidentiality, integrity, availability,
                    metric_source, metric_type, exploitability_score, impact_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    cv.version or "",
                    float(cv.score),
                    cv.vector or "",
                    cv.severity.value,
                    cv.attack_vector or "",
                    cv.attack_complexity or "",
                    cv.privileges_required or "",
                    cv.user_interaction or "",
                    cv.scope or "",
                    cv.confidentiality or "",
                    cv.integrity or "",
                    cv.availability or "",
                    cv.metric_source or "",
                    cv.metric_type or "",
                    float(cv.exploitability_score),
                    float(cv.impact_score),
                ),
            )


@dataclass(frozen=True, slots=True)
class CpeMatchUpsertStep:
    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        if not ctx.policy.cpe_matches:
            return
        cve_id = ctx.cve.cve_id
        for cm in ctx.cve.cpe_matches:
            crit = (cm.criteria or "").strip()
            if not crit:
                continue
            cur.execute(
                """
                INSERT INTO cpe_match (cve_id, criteria, match_criteria_id, vulnerable)
                VALUES (?, ?, ?, ?)
                """,
                (
                    cve_id,
                    crit,
                    (cm.match_criteria_id or "").strip(),
                    bool_to_sql(cm.vulnerable),
                ),
            )


@dataclass(frozen=True, slots=True)
class ExploitUpsertStep:
    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert an exploit.

        :param _sink: The sink.
        :type _sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        if not ctx.policy.exploit:
            return
        c = ctx.cve
        ex = c.exploit
        cur.execute(
            """
            INSERT INTO exploit (
                cve_id, maturity, public_poc, metasploit, ransomware_usage, in_the_wild, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                c.cve_id,
                ex.maturity.value,
                bool_to_sql_nullable(ex.public_poc),
                bool_to_sql_nullable(ex.metasploit),
                bool_to_sql(ex.ransomware_usage),
                bool_to_sql(ex.in_the_wild),
                ex.notes or "",
            ),
        )


@dataclass(frozen=True, slots=True)
class KevUpsertStep:
    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert a KEV.

        :param _sink: The sink.
        :type _sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        if not ctx.policy.kev:
            return
        c = ctx.cve
        kv = c.kev
        cur.execute(
            """
            INSERT INTO kev (
                cve_id, listed, date_added, due_date, notes,
                vulnerability_name, required_action, vendor_project, product_label,
                short_description, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                c.cve_id,
                bool_to_sql(kv.listed),
                date_to_sql(kv.date_added),
                date_to_sql(kv.due_date),
                kv.notes or "",
                kv.vulnerability_name or "",
                kv.required_action or "",
                kv.vendor_project or "",
                kv.product_label or "",
                kv.short_description or "",
                kv.source or "",
            ),
        )


@dataclass(frozen=True, slots=True)
class IntelUpsertStep:
    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert intel scores and string lists.

        :param _sink: The sink.
        :type _sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        if not ctx.policy.intel_scores and not ctx.policy.intel_string_lists:
            return
        c = ctx.cve
        ti = c.intel
        cve_id = c.cve_id
        if ctx.policy.intel_scores:
            cur.execute(
                """
                INSERT INTO intel (cve_id, epss_score, epss_percentile)
                VALUES (?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    epss_score = excluded.epss_score,
                    epss_percentile = excluded.epss_percentile
                """,
                (cve_id, float(ti.epss_score), float(ti.epss_percentile)),
            )
        if not ctx.policy.intel_string_lists:
            return
        for value in ti.known_actors:
            if not (value or "").strip():
                continue
            cur.execute(
                """
                INSERT INTO intel_string_list (cve_id, kind, value)
                VALUES (?, 'actor', ?)
                ON CONFLICT(cve_id, kind, value) DO NOTHING
                """,
                (cve_id, value.strip()),
            )
        for value in ti.malware_families:
            if not (value or "").strip():
                continue
            cur.execute(
                """
                INSERT INTO intel_string_list (cve_id, kind, value)
                VALUES (?, 'malware', ?)
                ON CONFLICT(cve_id, kind, value) DO NOTHING
                """,
                (cve_id, value.strip()),
            )
        for value in ti.campaigns:
            if not (value or "").strip():
                continue
            cur.execute(
                """
                INSERT INTO intel_string_list (cve_id, kind, value)
                VALUES (?, 'campaign', ?)
                ON CONFLICT(cve_id, kind, value) DO NOTHING
                """,
                (cve_id, value.strip()),
            )
        for value in ti.osv_packages:
            if not (value or "").strip():
                continue
            cur.execute(
                """
                INSERT INTO intel_string_list (cve_id, kind, value)
                VALUES (?, 'osv_package', ?)
                ON CONFLICT(cve_id, kind, value) DO NOTHING
                """,
                (cve_id, value.strip()),
            )


@dataclass(frozen=True, slots=True)
class ReferencesUpsertStep:
    def apply(
        self, _sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert references.

        :param _sink: The sink.
        :type _sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        if not ctx.policy.references:
            return
        cve_id = ctx.cve.cve_id
        for ref in ctx.cve.references:
            cur.execute(
                """
                INSERT INTO reference (cve_id, url, source, title, trust)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    ref.url or "",
                    ref.source or "",
                    ref.title or "",
                    ref.trust.value,
                ),
            )
            rid = cur.lastrowid
            for t in ref.tags:
                if not (t or "").strip():
                    continue
                cur.execute(
                    "INSERT OR IGNORE INTO reference_tag (reference_id, tag) VALUES (?, ?)",
                    (rid, t.strip()),
                )


@dataclass(frozen=True, slots=True)
class CveTagsUpsertStep:
    def apply(
        self, sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Insert CVE tags.

        :param sink: The sink.
        :type sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        if not ctx.policy.cve_tags:
            return
        cve_id = ctx.cve.cve_id
        for tag_name in ctx.cve.tags:
            if not (tag_name or "").strip():
                continue
            tid = sink.ensure_tag_id(cur, tag_name.strip())
            cur.execute(
                "INSERT OR IGNORE INTO cve_tag (cve_id, tag_id) VALUES (?, ?)",
                (cve_id, tid),
            )


@dataclass(frozen=True, slots=True)
class CveUpsertRegistry:
    """Ordered step list (registry). Swap or extend for custom write behavior."""

    steps: tuple[CveUpsertStep, ...]

    def run(
        self, sink: CveUpsertSink, cur: sqlite3.Cursor, ctx: CveUpsertContext
    ) -> None:
        """
        Run the CVE upsert registry.

        :param sink: The sink.
        :type sink: CveUpsertSink
        :param cur: The database cursor.
        :type cur: sqlite3.Cursor
        :param ctx: The CVE upsert context.
        :type ctx: CveUpsertContext
        """
        for step in self.steps:
            step.apply(sink, cur, ctx)


def default_cve_upsert_steps() -> tuple[CveUpsertStep, ...]:
    """Factory: built-in pipeline definition."""
    return (
        DeleteCveRowStep(),
        InsertCveCoreStep(),
        PrimaryVendorStep(),
        AffectedProductsStep(),
        AffectedVendorEdgesStep(),
        CweUpsertStep(),
        CvssUpsertStep(),
        CpeMatchUpsertStep(),
        ExploitUpsertStep(),
        KevUpsertStep(),
        IntelUpsertStep(),
        ReferencesUpsertStep(),
        CveTagsUpsertStep(),
    )


def intel_only_cve_upsert_steps() -> tuple[CveUpsertStep, ...]:
    """Update EPSS (and optionally intel string lists) without touching the rest of the graph."""
    return (IntelUpsertStep(),)


def intel_only_cve_upsert_registry() -> CveUpsertRegistry:
    return CveUpsertRegistry(steps=intel_only_cve_upsert_steps())


def default_cve_upsert_registry() -> CveUpsertRegistry:
    """
    Get the default CVE upsert registry.

    :return: The default CVE upsert registry.
    :rtype: CveUpsertRegistry
    """
    return CveUpsertRegistry(steps=default_cve_upsert_steps())


__all__ = [
    "AffectedProductsStep",
    "AffectedVendorEdgesStep",
    "CveTagsUpsertStep",
    "CveUpsertContext",
    "CveUpsertPolicy",
    "CveUpsertRegistry",
    "CveUpsertSink",
    "CveUpsertStep",
    "CpeMatchUpsertStep",
    "CweUpsertStep",
    "CvssUpsertStep",
    "DeleteCveRowStep",
    "ExploitUpsertStep",
    "InsertCveCoreStep",
    "IntelUpsertStep",
    "KevUpsertStep",
    "PrimaryVendorStep",
    "ReferencesUpsertStep",
    "default_cve_upsert_registry",
    "default_cve_upsert_steps",
    "intel_only_cve_upsert_registry",
    "intel_only_cve_upsert_steps",
]
