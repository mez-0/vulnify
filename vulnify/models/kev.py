from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


@dataclass(slots=True)
class KEVStatus:
    """
    KEVStatus model represents a KEV status.
    """
    
    """
    Listed model represents a listed.
    """
    listed: bool = field(default=False)
    
    """
    Date added model represents a date added.
    """
    date_added: date = field(default=date.min)
    
    """
    Due date model represents a due date.
    """
    due_date: date = field(default=date.min)
    
    """
    Notes model represents a notes.
    """
    notes: str = field(default_factory=str)

    """
    CISA vulnerability catalog title (or NVD cisaVulnerabilityName).
    """
    vulnerability_name: str = field(default_factory=str)

    """
    Required remediation directive (e.g. CISA requiredAction).
    """
    required_action: str = field(default_factory=str)

    """
    KEV vendor / project label from CISA catalog.
    """
    vendor_project: str = field(default_factory=str)

    """
    KEV product label from CISA catalog.
    """
    product_label: str = field(default_factory=str)

    """
    KEV short description from CISA catalog.
    """
    short_description: str = field(default_factory=str)

    """
    Provenance: ``cisa`` (catalog), ``nvd`` (NVD cisa* fields only), or empty.
    """
    source: str = field(default_factory=str)
