from __future__ import annotations

from dataclasses import dataclass, field

from vulnify.constants import Severity


@dataclass(slots=True)
class CVSS:
    """
    CVSS model represents a CVSS score.
    """
    
    """
    Version model represents a version.
    """
    version: str = field(default_factory=str)
    
    """
    Score model represents a score.
    """
    score: float = field(default_factory=float)
    
    """
    Vector model represents a vector.
    """
    vector: str = field(default_factory=str)
    
    """
    Severity model represents a severity.
    """
    severity: Severity = field(default=Severity.UNKNOWN)

    """
    Attack vector model represents an attack vector.
    """
    attack_vector: str = field(default_factory=str)
    
    """
    Attack complexity model represents an attack complexity.
    """
    attack_complexity: str = field(default_factory=str)
    
    """
    Privileges required model represents a privileges required.
    """
    privileges_required: str = field(default_factory=str)
    
    """
    User interaction model represents a user interaction.
    """
    user_interaction: str = field(default_factory=str)
    
    """
    Scope model represents a scope.
    """
    scope: str = field(default_factory=str)

    """
    Confidentiality model represents a confidentiality.
    """
    confidentiality: str = field(default_factory=str)
    
    """
    Integrity model represents an integrity.
    """
    integrity: str = field(default_factory=str)
    
    """
    Availability model represents an availability.
    """
    availability: str = field(default_factory=str)

    """
    Metric source (e.g. NVD email / org contributing this CVSS block).
    """
    metric_source: str = field(default_factory=str)

    """
    Metric type: Primary / Secondary (NVD CVSS metric role).
    """
    metric_type: str = field(default_factory=str)

    """
    NVD exploitability subscore (CVSS v3.x).
    """
    exploitability_score: float = field(default_factory=float)

    """
    NVD impact subscore (CVSS v3.x).
    """
    impact_score: float = field(default_factory=float)
