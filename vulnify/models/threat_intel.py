from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ThreatIntel:
    epss_score: float | None = None
    """
    EPSS probability, or ``None`` when FIRST has not scored the CVE.

    ⚠️ Never default this to ``0.0``: FIRST's floor is above zero, so ``0.0``
    reads as "scored, negligible" when the truth is "not scored" — the same
    collapse the exploit tri-state forbids.
    """
    epss_percentile: float | None = None

    """
    Known actors model represents a list of known actors.
    """
    known_actors: list[str] = field(default_factory=list)
    
    """
    Malware families model represents a list of malware families.
    """
    malware_families: list[str] = field(default_factory=list)
    
    """
    Campaigns model represents a list of campaigns.
    """
    campaigns: list[str] = field(default_factory=list)

    """
    OSV / GitHub affected packages as ``ecosystem:name`` strings.
    """
    osv_packages: list[str] = field(default_factory=list)
