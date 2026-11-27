"""Proses AI per temuan: panggil AI, periksa jawabannya, ulangi bila perlu, simpan cache."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .llm import ChatFn
from .periksa import parse_json, periksa
from .prompt import PROMPT_VERSION, SYSTEM_PROMPT, retry_prompt, user_prompt


def _cache_key(model: str, item: dict[str, Any]) -> str:
    # SYSTEM_PROMPT ikut dalam kunci: mengubah instruksi otomatis membuat cache lama tidak terpakai.
    payload = json.dumps(
        {"v": PROMPT_VERSION, "prompt": SYSTEM_PROMPT, "model": model, "asli": item["asli"],
         "kelas": item["findingClass"], "lokasi": item["temuan_itsa"].get("lokasi"),
         "method": item["temuan_itsa"].get("method"), "severity": item["temuan_itsa"].get("severity")},
        ensure_ascii=False, sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def tanya_ai(item: dict[str, Any], chat: ChatFn, max_percobaan: int) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    """Kembalikan (hasil, masalah_tersisa, catatan)."""
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
    for _ in range(max_percobaan):
        jawaban = chat(messages)
        masalah, hasil_baru, catatan = periksa(parse_json(jawaban), item["asli"])
        if hasil_baru is not None:
            hasil = hasil_baru
        if not masalah:
            return hasil, [], catatan
        messages += [{"role": "assistant", "content": jawaban}, {"role": "user", "content": retry_prompt(masalah)}]
    return hasil, masalah, catatan


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


def _baca_cache(path: Path) -> dict[str, Any] | None:
    """Cache yang tidak ada atau rusak (mis. terpotong karena laptop mati) dianggap tidak ada."""
    try:
        c = json.loads(path.read_text(encoding="utf-8"))
        return c if {"hasil", "masalah", "catatan"} <= c.keys() else None
    except (OSError, ValueError, AttributeError):
        return None


def proses_item(item: dict[str, Any], chat: ChatFn, model: str, cache_dir: Path,
                max_percobaan: int, pakai_cache: bool = True) -> None:
    """Proses satu temuan. LlmError (AI tidak bisa dihubungi) diteruskan ke pemanggil."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{_cache_key(model, item)}.json"
    c = _baca_cache(cache_file) if pakai_cache else None
    if c is not None:
        terapkan_ai(item, c["hasil"], c["masalah"], c["catatan"])
        return
    hasil, masalah, catatan = tanya_ai(item, chat, max_percobaan)
    tmp = cache_file.with_suffix(".tmp")
    tmp.write_text(json.dumps({"hasil": hasil, "masalah": masalah, "catatan": catatan},
                              ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, cache_file)  # tulis aman: file cache tidak pernah setengah jadi
    terapkan_ai(item, hasil, masalah, catatan)
