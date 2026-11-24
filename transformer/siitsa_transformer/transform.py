"""Transformasi JSON temuan ITS AI -> request body SIITSA.

Satu finding  -> satu body POST /api/temuan-itsa
Satu langkah reproSteps -> satu body POST /api/langkah-poc (request terpisah)

Format input yang diterima: lihat normalize.py (file *.findings.json maupun respons API engagement).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .normalize import FORMAT_LABELS, clean_text, detect_format, normalize_finding

FORMAT = "siitsa.temuan-import/v1"
# Status hasil validasi AI yang bukan "diterima": temuan tetap diproses, tapi diberi peringatan.
AI_STATUS_NOT_ACCEPTED = {"rejected", "inconclusive", "false-positive", "false_positive"}


class TransformError(ValueError):
    """Input bukan JSON temuan ITS AI yang valid."""


# ---------------------------------------------------------------- severity

# Label = pilihan dropdown Severity di form SIITSA, urut dari paling parah.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

_SEVERITY_ALIASES = {
    "critical": "Critical", "kritis": "Critical",
    "high": "High", "tinggi": "High",
    "medium": "Medium", "sedang": "Medium", "moderate": "Medium",
    "low": "Low", "rendah": "Low",
}


def severity_label(value: str | None) -> str:
    """Severity ITS AI -> label SIITSA; nilai tak dikenal (mis. "info") menjadi "Info"."""
    return _SEVERITY_ALIASES.get((value or "").strip().lower(), "Info")


def severity_from_cvss(score: float | None) -> str | None:
    """Rating dari skor CVSS (rentang v3.1 dan v4.0 sama); hanya untuk pembanding/peringatan."""
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


# ---------------------------------------------------------------- teks

# Paragraf baku AI tentang asumsi CVSS di akhir dampak, bukan bagian dampak.
_CVSS_NOTE = re.compile(r"^\s*(Asumsi CVSS|CVSS Attack Vector assumption)", re.IGNORECASE)


def clean_impact(value: Any) -> str:
    paragraphs = re.split(r"\n\s*\n", clean_text(value))
    return "\n\n".join(p for p in paragraphs if p.strip() and not _CVSS_NOTE.match(p)).strip()


# "1) ...", "1. ...", "1: ...", "Step 1. ..." di awal baris.
_STEP_START = re.compile(r"^\s*(?:step\s*)?(\d{1,3})\s*(?:[.):]|\s-)\s+(.*)$", re.IGNORECASE)


def split_repro_steps(text: Any) -> list[str]:
    """Pecah reproSteps menjadi daftar langkah.

    - Setiap baris baru = satu langkah.
    - Jika teks memakai penomoran (1., 2., ...), baris tanpa nomor berikutnya (mis. perintah curl
      yang menjorok) digabung ke langkah sebelumnya, supaya langkah tidak terpotong.
    - Nomor di awal baris dibuang karena urutan langkah = urutan pengiriman.
    """
    lines = [line for line in clean_text(text).split("\n") if line.strip()]
    if not lines:
        return []

    numbered = any(_STEP_START.match(line) for line in lines)
    steps: list[str] = []
    last_no: int | None = None
    for line in lines:
        m = _STEP_START.match(line)
        if not numbered:
            steps.append(line.strip())
            continue
        # Nomor dianggap langkah baru hanya jika urut (cegah salah tangkap angka di tengah teks).
        if m and (last_no is None or int(m.group(1)) == last_no + 1):
            last_no = int(m.group(1))
            steps.append(m.group(2).strip())
        elif steps:
            steps[-1] = f"{steps[-1]}\n{line.strip()}"
        else:
            steps.append(line.strip())
    return [s for s in steps if s]


def format_cvss(score: float | None) -> str:
    return "" if score is None else f"{score:.1f}"


# ---------------------------------------------------------------- per temuan

def transform_finding(
    finding: dict[str, Any],
    id_dok_aplikasi: Any = None,
    fmt: str | None = None,
    sertakan_gambar: bool = True,
) -> dict[str, Any]:
    n = normalize_finding(finding, fmt or detect_format({"findings": [finding]}))
    warnings: list[str] = []
    finding_class = n["finding_class"]

    is_candidate = finding_class.endswith(("-untested", "-candidate")) or "(candidate)" in n["title"]

    # severity: selalu dari ITS AI; skor CVSS hanya dibandingkan untuk peringatan.
    severity = severity_label(n["severity"])
    score = n["cvss_score"]
    cvss_sev = severity_from_cvss(score)
    if n["cvss_vector"] and score is None:
        warnings.append(f"Vektor CVSS '{n['cvss_vector']}' tidak bisa dihitung; kolom cvss dikosongkan.")
    elif not n["cvss_vector"]:
        warnings.append("Vektor CVSS kosong di JSON sumber.")
    if cvss_sev and cvss_sev != severity:
        warnings.append(
            f"Severity ITS AI '{severity}' berbeda dengan rating skor CVSS {format_cvss(score)} ('{cvss_sev}'); "
            f"tetap dipakai severity ITS AI."
        )

    # teks
    deskripsi = clean_text(n["description"])
    asumsi = clean_text(n["assumptions"])
    if asumsi:
        deskripsi = f"{deskripsi}\n\nAsumsi: {asumsi}" if deskripsi else f"Asumsi: {asumsi}"
    dampak = clean_impact(n["impact"])
    rekom = clean_text(n["remediation"])
    for name, value in (("deskripsi_khusus", deskripsi), ("dampak_khusus", dampak), ("rekom_khusus", rekom)):
        if not value:
            warnings.append(f"{name} kosong di JSON sumber.")
    if not n["lokasi"]:
        warnings.append("Lokasi kosong di JSON sumber.")

    if is_candidate:
        warnings.append("Temuan kandidat (belum teruji penuh); validator perlu memutuskan apakah dimasukkan.")
    if n["status_ai"].lower() in AI_STATUS_NOT_ACCEPTED:
        warnings.append(f"Status validasi AI '{n['status_ai']}'; validator perlu memutuskan apakah dimasukkan.")

    # id_kamus_kerentanan, perban4, owasptop10: tidak ada di data ITS AI, jadi selalu kosong
    # dan dipilih validator di SIITSA. Key tetap ada supaya body sama persis dengan form SIITSA.
    temuan_itsa = {
        "id_dok_aplikasi": id_dok_aplikasi,
        "id_kamus_kerentanan": None,
        "subjudul": n["title"],
        "perban4": "",
        "owasptop10": "",
        "lokasi": n["lokasi"],
        "deskripsi_khusus": deskripsi,
        "dampak_khusus": dampak,
        "rekom_khusus": rekom,
        "cvss": format_cvss(score),
        "cvss_string": n["cvss_vector"],
        "severity": severity,
        "method": n["method"],
        "status": "Open",
    }

    steps = split_repro_steps(n["repro_steps"])
    if not steps and n["walkthrough"]:
        steps = split_repro_steps(n["walkthrough"])
        warnings.append("reproSteps kosong; langkah POC diambil dari reproWalkthrough.")
    if not steps:
        warnings.append("reproSteps kosong; tidak ada langkah POC.")
    # {id_temuan, poc} = body persis POST /api/langkah-poc SIITSA; urutan langkah = urutan array.
    # gambar_poc (opsional) di-upload terpisah: POST /api/langkah-poc/{id}/gambarpoc (multipart).
    langkah_poc = [{"id_temuan": None, "poc": text, "gambar_poc": None} for text in steps]
    bukti_gambar = []
    shots = n["screenshots"] if sertakan_gambar else []
    for idx, shot in enumerate(shots, start=1):
        step = shot["langkah"]
        if step and 1 <= step <= len(langkah_poc) and langkah_poc[step - 1]["gambar_poc"] is None:
            langkah_poc[step - 1]["gambar_poc"] = {
                "nama_file": f"{n['ref'] or 'temuan'}-langkah-{step}.{shot['ext']}",
                "mime": shot["mime"],
                "keterangan": shot["keterangan"],
                "base64": shot["base64"],
            }
        else:
            bukti_gambar.append({
                "nama_file": f"{n['ref'] or 'temuan'}-bukti-{idx}.{shot['ext']}",
                "mime": shot["mime"],
                "keterangan": shot["keterangan"],
                "base64": shot["base64"],
            })
    if bukti_gambar:
        warnings.append(
            f"{len(bukti_gambar)} screenshot bukti belum terpasang ke langkah POC tertentu "
            "(lihat bukti_gambar); validator perlu memilih langkahnya."
        )

    return {
        "ref": n["ref"],
        "findingClass": finding_class,
        "status_ai": n["status_ai"],
        "verification": n["verification"],
        "temuan_itsa": temuan_itsa,
        "langkah_poc": langkah_poc,
        "bukti_gambar": bukti_gambar,
        "peringatan": warnings,
    }


# ---------------------------------------------------------------- laporan

def transform_report(
    data: Any,
    id_dok_aplikasi: int | str | None = None,
    source_name: str | None = None,
    sertakan_gambar: bool = True,
) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise TransformError("JSON tidak dikenali: harus berupa objek dengan array 'findings' (format ITS AI).")

    # Format selalu dideteksi otomatis dari isi file (findings.json dengan gambar / JSON API).
    fmt = detect_format(data)
    engagement = data.get("engagement") or {}
    engagement_id = clean_text(engagement.get("id")) or None
    # id_dok_aplikasi = id integer aplikasi di SIITSA (dikirim halaman upload SIITSA).
    # engagement.id ITS AI (UUID) hanya dicatat di "sumber", tidak dipakai sebagai id_dok_aplikasi.
    if id_dok_aplikasi in (None, ""):
        id_dok_aplikasi = None
    else:
        try:
            id_dok_aplikasi = int(id_dok_aplikasi)
        except (TypeError, ValueError) as exc:
            raise TransformError("id_dok_aplikasi harus berupa angka (id aplikasi di SIITSA).") from exc

    items = [
        transform_finding(f, id_dok_aplikasi, fmt, sertakan_gambar)
        for f in data["findings"]
        if isinstance(f, dict)
    ]
    # Urut severity (stabil: urutan asli dipertahankan dalam severity yang sama).
    items.sort(key=lambda t: severity_rank(t["temuan_itsa"]["severity"]))
    items = [{"no": no, **item} for no, item in enumerate(items, start=1)]

    per_severity = {label: 0 for label in SEVERITY_ORDER}
    for item in items:
        per_severity[item["temuan_itsa"]["severity"]] += 1

    peringatan_umum = []
    if id_dok_aplikasi is None:
        peringatan_umum.append("id_dok_aplikasi kosong; isi dengan id aplikasi SIITSA sebelum dikirim.")

    return {
        "format": FORMAT,
        "dibuat": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sumber": {
            "file": source_name,
            "format_input": fmt,
            "format_label": FORMAT_LABELS[fmt],
            "schema": data.get("schema"),
            "generatedAt": data.get("generatedAt") or engagement.get("createdAt"),
            "engagement_id": engagement_id,
            "engagement": engagement.get("name"),
            "scope": engagement.get("scopeIn") or [],
        },
        "id_dok_aplikasi": id_dok_aplikasi,
        "peringatan_umum": peringatan_umum,
        "ringkasan": {
            "jumlah_temuan": len(items),
            "jumlah_langkah_poc": sum(len(i["langkah_poc"]) for i in items),
            "per_severity": per_severity,
            "jumlah_gambar_poc": sum(1 for i in items for p in i["langkah_poc"] if p["gambar_poc"]),
            "jumlah_bukti_gambar": sum(len(i["bukti_gambar"]) for i in items),
            "jumlah_peringatan": sum(len(i["peringatan"]) for i in items),
        },
        "temuan": items,
    }
