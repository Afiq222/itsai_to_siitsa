"""Pemetaan deterministik: severity, Perban BSSN 4, OWASP Top 10, kamus kerentanan."""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("SIITSA_CONFIG_DIR", Path(__file__).resolve().parent.parent / "config"))

PERBAN4_LABELS = {
    "a": "a. autentikasi",
    "b": "b. manajemen sesi",
    "c": "c. persyaratan kontrol akses",
    "d": "d. validasi input",
    "e": "e. kriptografi pada verifikasi statis",
    "f": "f. penanganan eror dan pencatatan log",
    "g": "g. proteksi data",
    "h": "h. keamanan komunikasi",
    "i": "i. pengendalian kode berbahaya",
    "j": "j. logika bisnis",
    "k": "k. file",
    "l": "l. keamanan API dan web service",
    "m": "m. keamanan konfigurasi",
}

# Format owasptop10 mengikuti form SIITSA (placeholder "A01:2021", input teks bebas).
OWASP_SUFFIX = os.environ.get("SIITSA_OWASP_SUFFIX", ":2021")
OWASP_CODES = {f"A{i:02d}" for i in range(1, 11)}

# Label = pilihan dropdown Severity di form SIITSA.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

_SEVERITY_ALIASES = {
    "critical": "Critical", "kritis": "Critical",
    "high": "High", "tinggi": "High",
    "medium": "Medium", "sedang": "Medium", "moderate": "Medium",
    "low": "Low", "rendah": "Low",
}


@lru_cache(maxsize=None)
def _load(name: str) -> dict[str, str]:
    path = CONFIG_DIR / name
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return {str(k).lower(): str(v) for k, v in data.get("map", {}).items()}


def class_candidates(finding_class: str) -> list[str]:
    c = (finding_class or "").strip().lower()
    base = re.sub(r"-(untested|candidate)$", "", c)
    return [x for x in dict.fromkeys([c, base]) if x]


def _lookup(name: str, finding_class: str) -> str | None:
    table = _load(name)
    for c in class_candidates(finding_class):
        if c in table:
            return table[c]
    return None


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


def perban4(finding_class: str) -> str | None:
    letter = _lookup("perban4.json", finding_class)
    return PERBAN4_LABELS.get(letter or "")


def owasp(finding_class: str) -> str | None:
    """Nilai owasptop10 dari tabel; None jika findingClass tidak terpetakan (tanpa tebakan)."""
    code = _lookup("owasp.json", finding_class)
    return code + OWASP_SUFFIX if code in OWASP_CODES else None


def kamus_kerentanan(finding_class: str) -> int | None:
    value = _lookup("kamus_kerentanan.json", finding_class)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
