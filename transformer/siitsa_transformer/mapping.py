"""Label dan urutan severity (mengikuti pilihan dropdown Severity di form SIITSA)."""

from __future__ import annotations

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

_SEVERITY_ALIASES = {
    "critical": "Critical", "kritis": "Critical",
    "high": "High", "tinggi": "High",
    "medium": "Medium", "sedang": "Medium", "moderate": "Medium",
    "low": "Low", "rendah": "Low",
}


def severity_label(value: str | None) -> str:
    return _SEVERITY_ALIASES.get((value or "").strip().lower(), "Info")


def severity_from_cvss(score: float | None) -> str | None:
    """Rentang rating CVSS (v3.1 dan v4.0 sama)."""
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Info"


def severity_rank(label: str) -> int:
    return SEVERITY_ORDER.index(label) if label in SEVERITY_ORDER else len(SEVERITY_ORDER)
