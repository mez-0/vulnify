from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class VersionRange:
    """
    Canonical version range model.
    Supports:
      >= 1.0.0
      > 1.0.0
      <= 2.0.0
      < 2.0.0
    """
    start_including: str = field(default_factory=str)
    start_excluding: str = field(default_factory=str)
    end_including: str = field(default_factory=str)
    end_excluding: str = field(default_factory=str)
    fixed_version: str = field(default_factory=str)
    raw_text: str = field(default_factory=str)
