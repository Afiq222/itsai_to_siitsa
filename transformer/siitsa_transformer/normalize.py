"""Menyeragamkan dua format JSON ITS AI menjadi satu bentuk internal.

Format yang dikenali:
- "findings-export": file *.findings.json (schema vacti.findings/v1) — finding punya `ref`,
  `cvssScore`, `cvssVector`, `affected{url,parameter,method}`, `narrative{...}`.
- "api-response":    respons API engagement (engagement.id + findings[]) — finding punya `id`,
  `cvss` (vektor saja), `location` ("METHOD url (param x)"), `description`, `impact`,
  `reproSteps`, `locales{...Id,...En}`.
"""

from __future__ import annotations

import re
from typing import Any

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError

HTTP_METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT"


def clean_text(value: Any) -> str:
    """Normalisasi teks: newline seragam, spasi ujung baris dibuang, baris kosong berlebih dirapatkan."""
    if value is None:
        return ""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


FORMAT_LABELS = {
    "findings-export": "JSON dengan gambar",
    "api-response": "JSON tanpa gambar",
}


def detect_format(data: dict[str, Any]) -> str:
    if data.get("schema", "").startswith("vacti.findings"):
        return "findings-export"
    first = next((f for f in data.get("findings", []) if isinstance(f, dict)), {})
    if "narrative" in first or "affected" in first or "cvssScore" in first:
        return "findings-export"
    return "api-response"


def cvss_score(vector: str) -> float | None:
    """Hitung base score dari vektor CVSS 3.x / 4.0; None jika vektor kosong/tidak valid."""
    vector = (vector or "").strip()
    try:
        if vector.startswith("CVSS:4.0/"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3."):
            return float(CVSS3(vector).base_score)
    except (CVSSError, ValueError, KeyError):
        return None
    return None


def split_location(location: str) -> tuple[str, str]:
    """'POST https://x/api (param a, b)' -> ('POST', 'https://x/api (parameter: a, b)')."""
    rest = clean_text(location)
    method = ""
    m = re.match(rf"^({HTTP_METHODS})\s+(.+)$", rest, re.IGNORECASE | re.DOTALL)
    if m:
        method, rest = m.group(1).upper(), m.group(2).strip()
    m = re.match(r"^(\S+)\s+\(param\s+(.*)\)\s*$", rest, re.IGNORECASE | re.DOTALL)
    if m:
        rest = f"{m.group(1)} (parameter: {m.group(2).strip()})"
    return method, rest


def _lokasi_from_affected(affected: dict[str, Any]) -> str:
    url = clean_text(affected.get("url")) or clean_text(affected.get("host"))
    param = clean_text(affected.get("parameter"))
    if param and param not in url:
        return f"{url} (parameter: {param})" if url else f"parameter: {param}"
    return url


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


_DATA_URI = re.compile(r"^data:(image/[a-z0-9.+-]+);base64,(.+)$", re.IGNORECASE | re.DOTALL)
_STEP_CAPTION = re.compile(r"\bstep\s+(\d{1,3})\s*/\s*(\d{1,3})\b", re.IGNORECASE)
_EXT = {"image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/gif": "gif", "image/webp": "webp"}


def extract_screenshots(evidence: Any) -> list[dict[str, Any]]:
    """Ambil screenshot base64 dari evidence[] (format findings-export).

    Setiap item: {"langkah": int|None, "mime", "ext", "keterangan", "base64"}.
    "langkah" terisi jika keterangan berbunyi "step i/n".
    """
    shots = []
    for e in evidence or []:
        if not isinstance(e, dict) or not e.get("image"):
            continue
        m = _DATA_URI.match(str(e["image"]).strip())
        if not m:
            continue
        mime = m.group(1).lower()
        caption = clean_text(e.get("caption"))
        step = _STEP_CAPTION.search(caption)
        shots.append({
            "langkah": int(step.group(1)) if step else None,
            "mime": mime,
            "ext": _EXT.get(mime, mime.split("/")[-1]),
            "keterangan": caption,
            "base64": re.sub(r"\s+", "", m.group(2)),
        })
    return shots


def normalize_finding(f: dict[str, Any], fmt: str) -> dict[str, Any]:
    if fmt == "findings-export":
        narrative = f.get("narrative") or {}
        affected = f.get("affected") or {}
        vector = clean_text(f.get("cvssVector"))
        score = _num(f.get("cvssScore"))
        return {
            "ref": clean_text(f.get("ref")) or clean_text(f.get("id")),
            "title": clean_text(f.get("title")),
            "severity": clean_text(f.get("severity")),
            "cvss_vector": vector,
            "cvss_score": score if score is not None else cvss_score(vector),
            "finding_class": clean_text(f.get("findingClass")).lower(),
            "status_ai": clean_text(f.get("status")),
            "verification": clean_text(f.get("verification")),
            "method": clean_text(affected.get("method")).upper(),
            "lokasi": _lokasi_from_affected(affected),
            "description": narrative.get("description"),
            "impact": narrative.get("businessImpact"),
            "remediation": narrative.get("remediation"),
            "assumptions": narrative.get("assumptions"),
            "repro_steps": narrative.get("reproSteps"),
            "walkthrough": None,
            "screenshots": extract_screenshots(f.get("evidence")),
        }

    # api-response: utamakan teks Bahasa Indonesia di locales, lalu field utama.
    loc = f.get("locales") or {}

    def pick(locale_key: str, top_key: str) -> str:
        return clean_text(loc.get(locale_key)) or clean_text(f.get(top_key))

    vector = clean_text(f.get("cvss") or f.get("cvssVector"))
    score = _num(f.get("cvssScore"))
    method, lokasi = split_location(clean_text(f.get("location")))
    return {
        "ref": clean_text(f.get("id")) or clean_text(f.get("ref")),
        "title": clean_text(f.get("title")),
        "severity": clean_text(f.get("severity")),
        "cvss_vector": vector,
        "cvss_score": score if score is not None else cvss_score(vector),
        "finding_class": clean_text(f.get("findingClass")).lower(),
        "status_ai": clean_text(f.get("status")),
        "verification": clean_text(f.get("verification")),
        "method": method,
        "lokasi": lokasi,
        "description": pick("descriptionId", "description"),
        "impact": pick("businessImpactId", "impact"),
        "remediation": pick("remediationId", "remediation"),
        "assumptions": f.get("assumptions"),
        "repro_steps": pick("reproStepsId", "reproSteps"),
        "walkthrough": pick("reproWalkthroughId", "reproWalkthrough"),
        # Format API tidak membawa gambar; dukung evidence[] jika suatu saat ikut disertakan.
        "screenshots": extract_screenshots(f.get("evidence")),
    }
