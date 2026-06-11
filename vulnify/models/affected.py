from __future__ import annotations

from dataclasses import dataclass, field

from vulnify.models.vendor import Product
from vulnify.models.version import VersionRange


@dataclass(slots=True)
class AffectedProduct:
    """
    AffectedProduct model represents a product that is affected by a vulnerability.
    """
    
    """
    Product model represents a product that is affected by a vulnerability.
    """
    product: Product = field(default_factory=Product)
    
    """
    VersionRange model represents a version range that is affected by a vulnerability.
    """
    versions: list[VersionRange] = field(default_factory=list)
    
    """
    Affected model represents a product that is affected by a vulnerability.
    """
    affected: bool = field(default=True)
    
    """
    Notes model represents a note that is affected by a vulnerability.
    """
    notes: str = field(default_factory=str)
