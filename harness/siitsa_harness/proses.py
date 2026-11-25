"""Proses AI per temuan: panggil AI lokal, periksa jawabannya, ulangi bila perlu, simpan cache."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .llm import ChatFn, LlmError
from .periksa import parse_json, periksa
from .prompt import PROMPT_VERSION, SYSTEM_PROMPT, retry_prompt, user_prompt


def _cache_key(model: str, item: dict[str, Any]) -> str:
    payload = json.dumps(
        {"v": PROMPT_VERSION, "model": model, "asli": item["asli"], "kelas": item["findingClass"],
         "lokasi": item["temuan_itsa"].get("lokasi"), "method": item["temuan_itsa"].get("method"),
         "severity": item["temuan_itsa"].get("severity")},
        ensure_ascii=False, sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def tanya_ai(item: dict[str, Any], chat: ChatFn, max_percobaan: int) -> tuple[dict[str, Any] | None, list[str], list[str], int]:
    """Kembalikan (hasil, masalah_tersisa, catatan, jumlah_percobaan)."""
    konteks = {
        "findingClass": item["findingClass"],
        "severity": item["temuan_itsa"].get("severity", ""),
        "method": item["temuan_itsa"].get("method", ""),
        "lokasi": item["temuan_itsa"].get("lokasi", ""),
    }
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt(item["asli"], konteks)},
    ]
    hasil, masalah, catatan = None, ["AI belum menjawab."], []
    for percobaan in range(1, max_percobaan + 1):
        jawaban = chat(messages)
        masalah, hasil_baru, catatan = periksa(parse_json(jawaban), item["asli"])
        if hasil_baru is not None:
            hasil = hasil_baru
        if not masalah:
            return hasil, [], catatan, percobaan
        messages += [{"role": "assistant", "content": jawaban}, {"role": "user", "content": retry_prompt(masalah)}]
    return hasil, masalah, catatan, max_percobaan


def terapkan_ai(item: dict[str, Any], hasil: dict[str, Any] | None, masalah: list[str], catatan: list[str]) -> None:
    """Pasang hasil AI ke temuan: versi AI disimpan, kolom 'hasil' (yang diedit validator) diisi darinya."""
    item["error_ai"] = None
    if hasil is None:
        item["ai"] = None
        item["status"] = "perlu_cek"
        item["catatan_ai"] = ["AI tidak memberi jawaban JSON yang sah; teks asli dipertahankan."]
        return
    item["ai"] = hasil
    rek = hasil["rekomendasi"]
    item["hasil"] = {
        "subjudul": hasil["subjudul"],
        "deskripsi_khusus": hasil["deskripsi_khusus"],
        "dampak_khusus": hasil["dampak_khusus"],
        "rekom_khusus": hasil["rekom_khusus"],
        "langkah_poc": list(hasil["langkah_poc"]),
        "perban4": rek["perban4"]["nilai"],
        "owasptop10": rek["owasptop10"]["nilai"],
        "id_kamus_kerentanan": rek["id_kamus_kerentanan"]["nilai"],
    }
    item["kategori_sumber"] = {
        k: ("rekomendasi_ai" if rek[k]["nilai"] not in ("", None) else "kosong")
        for k in ("perban4", "owasptop10", "id_kamus_kerentanan")
    }
    item["catatan_ai"] = list(catatan)
    if masalah:
        item["catatan_ai"].append("Masih ada masalah setelah semua percobaan: " + " ".join(masalah))
    item["status"] = "perlu_cek" if (masalah or catatan) else "draf"


def proses_item(item: dict[str, Any], chat: ChatFn, model: str, cache_dir: Path,
                max_percobaan: int, pakai_cache: bool = True) -> None:
    """Proses satu temuan. LlmError (AI tidak bisa dihubungi) diteruskan ke pemanggil."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{_cache_key(model, item)}.json"
    if pakai_cache and cache_file.is_file():
        c = json.loads(cache_file.read_text(encoding="utf-8"))
        terapkan_ai(item, c["hasil"], c["masalah"], c["catatan"])
        return
    hasil, masalah, catatan, _ = tanya_ai(item, chat, max_percobaan)
    cache_file.write_text(json.dumps({"hasil": hasil, "masalah": masalah, "catatan": catatan},
                                     ensure_ascii=False), encoding="utf-8")
    terapkan_ai(item, hasil, masalah, catatan)


__all__ = ["LlmError", "proses_item", "tanya_ai", "terapkan_ai"]
