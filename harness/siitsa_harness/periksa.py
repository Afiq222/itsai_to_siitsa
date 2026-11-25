"""Pemeriksaan jawaban AI oleh kode (bukan oleh AI).

periksa() mengembalikan:
- masalah : daftar pelanggaran yang membuat AI diminta mengulang;
- hasil   : versi terbaik yang aman dipakai. Bagian yang melanggar diganti teks asli
            (mis. langkah POC yang kehilangan URL/perintah memakai langkah asli);
- catatan : penjelasan bagian mana yang diganti, untuk validator.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .prompt import BATAS, KAMUS, OWASP, OWASP_TAHUN, PERBAN4

_URL = re.compile(r"https?://[^\s`'\"<>)\]]+")
_BACKTICK = re.compile(r"`([^`\n]+)`")
_NUMBER = re.compile(r"\b\d{1,3}(?:[.,]\d{3})+\b|\b\d{3,}\b")


def parse_json(text: str) -> dict[str, Any] | None:
    """Ambil objek JSON dari jawaban AI (toleran terhadap ```json ...``` atau teks di sekitarnya)."""
    text = (text or "").strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def token_penting(langkah: str) -> list[str]:
    """Potongan teknis yang wajib tetap ada di versi ringkas sebuah langkah POC."""
    tokens: list[str] = []
    tokens += [u.rstrip(".,;:") for u in _URL.findall(langkah)]
    tokens += [b.strip() for b in _BACKTICK.findall(langkah) if b.strip()]
    tokens += [line.strip() for line in langkah.split("\n") if line.strip().lower().startswith("curl ")]
    tokens += _NUMBER.findall(langkah)
    return list(dict.fromkeys(t for t in tokens if t))


def token_hilang(asli: str, ringkas: str) -> list[str]:
    teks = _norm(ringkas)
    angka = re.sub(r"[.,]", "", teks)
    hilang = []
    for t in token_penting(asli):
        if _NUMBER.fullmatch(t):
            if re.sub(r"[.,]", "", t) not in angka:
                hilang.append(t)
        elif _norm(t) not in teks:
            hilang.append(t)
    return hilang


def _poin(value: Any) -> list[str] | None:
    if isinstance(value, str):
        value = [v for v in value.split("\n")]
    if not isinstance(value, list):
        return None
    items = [re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", str(v)).strip() for v in value]
    return [i for i in items if i]


def ke_teks_poin(items: list[str]) -> str:
    return "\n".join(f"- {i}" for i in items)


def periksa(data: dict[str, Any] | None, asli: dict[str, Any]) -> tuple[list[str], dict[str, Any] | None, list[str]]:
    if data is None:
        return ["Jawaban bukan objek JSON."], None, []

    masalah: list[str] = []
    catatan: list[str] = []
    hasil: dict[str, Any] = {}

    # subjudul
    sub = _norm(str(data.get("subjudul") or ""))
    if not sub:
        masalah.append("'subjudul' kosong.")
        hasil["subjudul"] = asli["subjudul"]
        catatan.append("Subjudul memakai teks asli (AI tidak memberi).")
    elif len(sub) > BATAS["subjudul"]:
        masalah.append(f"'subjudul' {len(sub)} karakter, maksimal {BATAS['subjudul']}.")
        hasil["subjudul"] = asli["subjudul"]
        catatan.append("Subjudul AI terlalu panjang; memakai teks asli.")
    else:
        hasil["subjudul"] = sub

    # deskripsi, dampak, rekomendasi -> poin
    for kunci, field in (("deskripsi", "deskripsi_khusus"), ("dampak", "dampak_khusus"), ("rekomendasi", "rekom_khusus")):
        items = _poin(data.get(kunci))
        if not items:
            masalah.append(f"'{kunci}' harus daftar poin dan tidak boleh kosong.")
            hasil[field] = asli[field]
            catatan.append(f"{field} memakai teks asli (AI tidak memberi poin).")
            continue
        panjang = [i for i in items if len(i) > BATAS["poin"]]
        if len(items) > BATAS["jumlah_poin"]:
            masalah.append(f"'{kunci}' {len(items)} poin, maksimal {BATAS['jumlah_poin']}.")
        if panjang:
            masalah.append(f"Ada poin '{kunci}' lebih dari {BATAS['poin']} karakter; persingkat.")
        hasil[field] = ke_teks_poin(items)
        if kunci == "dampak" and not asli[field]:
            catatan.append("Dampak disusun AI dari deskripsi karena di data ITS AI kosong; mohon dicek.")

    # langkah POC: jumlah sama, potongan teknis tidak boleh hilang
    poc_asli: list[str] = asli["langkah_poc"]
    poc_ai = data.get("langkah_poc")
    if not isinstance(poc_ai, list) or len(poc_ai) != len(poc_asli):
        n = len(poc_ai) if isinstance(poc_ai, list) else 0
        masalah.append(f"'langkah_poc' harus berisi tepat {len(poc_asli)} langkah (diberikan {n}).")
        hasil["langkah_poc"] = list(poc_asli)
        if poc_asli:
            catatan.append("Langkah POC memakai teks asli (jumlah langkah dari AI tidak sesuai).")
    else:
        hasil["langkah_poc"] = []
        for i, (a, r) in enumerate(zip(poc_asli, poc_ai), start=1):
            r = str(r or "").strip()
            hilang = token_hilang(a, r) if r else ["(langkah kosong)"]
            if hilang:
                masalah.append(f"Langkah POC {i} kehilangan bagian teknis: {', '.join(hilang[:5])}.")
                hasil["langkah_poc"].append(a)
                catatan.append(f"Langkah POC {i} memakai teks asli (versi AI menghilangkan bagian teknis).")
            else:
                hasil["langkah_poc"].append(r)

    # rekomendasi kategori
    rek: dict[str, dict[str, Any]] = {}
    huruf = str(data.get("perban4") or "").strip().lower()[:1]
    if huruf in PERBAN4:
        rek["perban4"] = {"nilai": PERBAN4[huruf], "alasan": _norm(str(data.get("alasan_perban4") or ""))}
    else:
        masalah.append("'perban4' harus satu huruf a sampai m.")
        rek["perban4"] = {"nilai": "", "alasan": ""}
    kode = str(data.get("owasptop10") or "").strip().upper()[:3]
    if kode in OWASP:
        rek["owasptop10"] = {"nilai": f"{kode}:{OWASP_TAHUN}", "alasan": _norm(str(data.get("alasan_owasp") or ""))}
    else:
        masalah.append("'owasptop10' harus kode A01 sampai A10.")
        rek["owasptop10"] = {"nilai": "", "alasan": ""}
    kamus = data.get("id_kamus_kerentanan")
    try:
        kamus = None if kamus in (None, "", "null") else int(kamus)
    except (TypeError, ValueError):
        kamus = -1
    if kamus is None or kamus in KAMUS:
        rek["id_kamus_kerentanan"] = {"nilai": kamus, "alasan": _norm(str(data.get("alasan_kamus") or ""))}
    else:
        masalah.append(f"'id_kamus_kerentanan' harus angka 1 sampai {max(KAMUS)} atau null.")
        rek["id_kamus_kerentanan"] = {"nilai": None, "alasan": ""}
    hasil["rekomendasi"] = rek

    return masalah, hasil, catatan
