from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from vulnify.constants import Severity, SourceTrust
from vulnify.models.affected import AffectedProduct
from vulnify.models.cpe import CpeMatch
from vulnify.models.cvss import CVSS
from vulnify.models.cwe import CWE
from vulnify.models.exploit import ExploitInfo
from vulnify.models.kev import KEVStatus
from vulnify.models.reference import Reference
from vulnify.models.threat_intel import ThreatIntel
from vulnify.models.vendor import Vendor


def _missing_date_sentinel() -> datetime:
    """Placeholder when CVE timestamps are unknown (bare ``datetime`` is not a zero-arg callable)."""
    return datetime.min.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class CVE:
    """
    CVE model represents a CVE record.
    """

    """
    CVE ID model represents a CVE ID.
    """
    cve_id: str = field(default_factory=str)

    """
    Title model represents a title.
    """
    title: str = field(default_factory=str)

    """
    CNA model represents a CNA.
    """
    cna: str = field(default_factory=str)

    """
    Primary vendor model represents a primary vendor.
    """
    primary_vendor: Vendor = field(default_factory=Vendor)

    """
    Published model represents a published date.
    """
    published: datetime = field(default_factory=_missing_date_sentinel)

    """
    Modified model represents a modified date.
    """
    modified: datetime = field(default_factory=_missing_date_sentinel)

    """
    Discovered model represents a discovered date.
    """
    discovered: datetime = field(default_factory=_missing_date_sentinel)

    """
    Summary model represents a summary.
    """
    summary: str = field(default_factory=str)

    """
    Technical details model represents a technical details.
    """
    technical_details: str = field(default_factory=str)

    """
    NVD vulnerability status (e.g. Analyzed).
    """
    vuln_status: str = field(default_factory=str)

    """
    NVD CVE sourceIdentifier (submitter).
    """
    source_identifier: str = field(default_factory=str)

    """
    CWEs model represents a list of CWEs.
    """
    cwes: list[CWE] = field(default_factory=list)

    """
    CVSS scores model represents a list of CVSS scores.
    """
    cvss_scores: list[CVSS] = field(default_factory=list)

    """
    Affected products model represents a list of affected products.
    """
    affected_products: list[AffectedProduct] = field(default_factory=list)

    """
    NVD CPE match rows (inventory-oriented).
    """
    cpe_matches: list[CpeMatch] = field(default_factory=list)

    """
    Exploit model represents an exploit.
    """
    exploit: ExploitInfo = field(default_factory=ExploitInfo)

    """
    KEV model represents a KEV status.
    """
    kev: KEVStatus = field(default_factory=KEVStatus)

    """
    Intel model represents an intel.
    """
    intel: ThreatIntel = field(default_factory=ThreatIntel)

    """
    References model represents a list of references.
    """
    references: list[Reference] = field(default_factory=list)

    """
    Tags model represents a list of tags.
    """
    tags: list[str] = field(default_factory=list)

    """
    Priority score model represents a priority score.
    """
    priority_score: int = field(default_factory=int)

    """
    Confidence model represents a confidence.
    """
    confidence: float = field(default=1.0)

    """
    Extra model represents extra data.
    """
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def highest_cvss(self) -> CVSS | None:
        """
        Get the highest CVSS score.

        :return: The highest CVSS score, or None when there are no CVSS scores.
        :rtype: CVSS | None
        """
        if not self.cvss_scores:
            return None
        return max(self.cvss_scores, key=lambda x: x.score)

    @property
    def severity(self) -> Severity:
        """
        Get the severity of the CVE.

        :return: The severity of the CVE.
        :rtype: Severity
        """
        top = self.highest_cvss
        return top.severity if top else Severity.UNKNOWN

    @property
    def actively_exploited(self) -> bool:
        """
        Check if the CVE is actively exploited.

        :return: True if the CVE is actively exploited, False otherwise.
        :rtype: bool
        """
        return self.kev.listed or self.exploit.in_the_wild

    @property
    def internet_critical(self) -> bool:
        """
        Check if the CVE is internet critical.

        :return: True if the CVE is internet critical, False otherwise.
        :rtype: bool
        """
        return self.remote and self.unauthenticated and self.rce

    @property
    def remote(self) -> bool:
        """
        Check if the CVE is remote.

        :return: True if the CVE is remote, False otherwise.
        :rtype: bool
        """
        cv = self.highest_cvss
        if cv is None:
            return False
        return (cv.attack_vector or "").upper() == "NETWORK"

    @property
    def unauthenticated(self) -> bool:
        """
        Check if the CVE is unauthenticated.

        :return: True if the CVE is unauthenticated, False otherwise.
        :rtype: bool
        """
        cv = self.highest_cvss
        if cv is None:
            return False
        return (cv.privileges_required or "").upper() == "NONE" and (
            cv.user_interaction or ""
        ).upper() == "NONE"

    @property
    def rce(self) -> bool:
        """
        Check if the CVE is RCE.

        :return: True if the CVE is RCE, False otherwise.
        :rtype: bool
        """
        cv = self.highest_cvss
        if cv is None:
            return False
        return (cv.integrity or "").upper() == "HIGH" and self.remote

    def add_reference(self, url: str, source: str, trust: SourceTrust):
        """
        Add a reference to the CVE.

        :param url: The URL of the reference.
        :type url: str
        :param source: The source of the reference.
        :type source: str
        :param trust: The trust of the reference.
        :type trust: SourceTrust
        """
        self.references.append(Reference(url=url, source=source, trust=trust))
