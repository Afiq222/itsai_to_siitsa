"""Membaca file masukan harness.

Masukan utama adalah hasil transformer (<nama>.siitsa.json). Jika yang diberikan masih JSON
mentah ITS AI, transformer (folder ../transformer di repo yang sama) dijalankan dulu. Transformer
sendiri tidak diubah dan tetap tanpa AI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

FORMAT_SIITSA = "siitsa.temuan-import/v1"
TRANSFORMER_DIR = Path(__file__).resolve().parent.parent.parent / "transformer"


class MasukanError(ValueError):
    """File tidak bisa dipakai sebagai masukan harness."""


def baca_bytes(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MasukanError(f"File bukan JSON yang valid: {exc}") from exc


def ke_format_siitsa(data: Any, nama_file: str | None, id_dok_aplikasi: int | None) -> dict[str, Any]:
    if isinstance(data, dict) and data.get("format") == FORMAT_SIITSA and isinstance(data.get("temuan"), list):
        hasil = data
    elif isinstance(data, dict) and isinstance(data.get("findings"), list):
        hasil = _jalankan_transformer(data, nama_file, id_dok_aplikasi)
    else:
        raise MasukanError(
            "File tidak dikenali: berikan hasil transformer (*.siitsa.json) atau JSON temuan ITS AI."
        )
    if id_dok_aplikasi is not None:
        hasil["id_dok_aplikasi"] = id_dok_aplikasi
        for t in hasil["temuan"]:
            t["temuan_itsa"]["id_dok_aplikasi"] = id_dok_aplikasi
    return hasil


def _jalankan_transformer(data: dict[str, Any], nama_file: str | None, id_dok_aplikasi: int | None) -> dict[str, Any]:
    if str(TRANSFORMER_DIR) not in sys.path:
        sys.path.insert(0, str(TRANSFORMER_DIR))
    try:
        from siitsa_transformer import TransformError, transform_report
    except ImportError as exc:
        raise MasukanError(f"Transformer tidak ditemukan di {TRANSFORMER_DIR}: {exc}") from exc
    try:
        return transform_report(data, id_dok_aplikasi, nama_file)
    except TransformError as exc:
        raise MasukanError(str(exc)) from exc
