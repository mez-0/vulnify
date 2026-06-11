from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ThreatIntel:
    epss_score: float = field(default_factory=float)
    """
    EPPs percentile model represents a EPPs percentile.
    """
    epss_percentile: float = field(default_factory=float)
    
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
