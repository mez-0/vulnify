from __future__ import annotations

from dataclasses import dataclass, field

from vulnify.constants import SourceTrust


@dataclass(slots=True)
class Reference:
    """
    Reference model represents a reference.
    """
    
    """
    URL model represents a URL.
    """
    url: str = field(default_factory=str)
    """
    Source model represents a source.
    """
    source: str = field(default_factory=str)
    
    """
    Title model represents a title.
    """
    title: str = field(default_factory=str)
    
    """
    Tags model represents a list of tags.
    """
    tags: list[str] = field(default_factory=list)
    
    """
    Trust model represents a trust.
    """
    trust: SourceTrust = field(default=SourceTrust.COMMUNITY)
