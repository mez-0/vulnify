from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CWE:
    """
    CWE model represents a CWE.
    """
    
    """
    CWE ID model represents a CWE ID.
    """
    cwe_id: str = field(default_factory=str)
    """
    Name model represents a name.
    """
    name: str = field(default_factory=str)
    
    """
    Description model represents a description.
    """
    description: str = field(default_factory=str)
