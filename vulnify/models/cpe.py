from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CpeMatch:
    """Single NVD CPE 2.3 match criteria (from ``configurations``)."""

    criteria: str = field(default_factory=str)
    match_criteria_id: str = field(default_factory=str)
    vulnerable: bool = field(default=True)
