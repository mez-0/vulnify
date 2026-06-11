"""Map CVSS ``baseSeverity`` / base score to :class:`~vulnify.constants.Severity` (NVD-style bands)."""

from __future__ import annotations

from vulnify.constants import Severity

# Descending score floors — first match wins (aligns with NVD CVSS v3 qualitative ratings).
CVSS_BASE_SCORE_SEVERITY_REGISTRY: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.0, Severity.LOW),
)


def severity_from_cvss_base(base_severity: str | None, base_score: float) -> Severity:
    """
    Resolve severity from optional CNA/NVD ``baseSeverity`` string and numeric base score.

    When ``base_severity`` is a known :class:`~vulnify.constants.Severity` name it wins;
    otherwise the score is mapped via :data:`CVSS_BASE_SCORE_SEVERITY_REGISTRY`.
    Scores ``<= 0`` yield ``UNKNOWN`` (no positive band).
    """
    if base_severity:
        normalized = base_severity.upper()
        if normalized in Severity.__members__:
            return Severity[normalized]
    if base_score <= 0:
        return Severity.UNKNOWN
    for floor, level in CVSS_BASE_SCORE_SEVERITY_REGISTRY:
        if base_score >= floor:
            return level
    return Severity.UNKNOWN


__all__ = [
    "CVSS_BASE_SCORE_SEVERITY_REGISTRY",
    "severity_from_cvss_base",
]
