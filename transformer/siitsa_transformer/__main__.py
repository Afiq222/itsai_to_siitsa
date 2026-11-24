"""CLI: python -m siitsa_transformer input.findings.json [-o output.json] [--id-dok-aplikasi 1]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .transform import TransformError, transform_report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="siitsa_transformer", description="JSON temuan ITS AI -> JSON SIITSA")
    p.add_argument("input", type=Path, help="file JSON ITS AI (*.findings.json atau JSON API; format dideteksi otomatis)")
    p.add_argument("-o", "--output", type=Path, help="file output (default: output/<nama>.siitsa.json)")
    p.add_argument("--id-dok-aplikasi", type=int, default=None, help="id_dok_aplikasi di SIITSA")
    p.add_argument("--tanpa-gambar", action="store_true", help="abaikan screenshot evidence")
    args = p.parse_args(argv)

    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        result = transform_report(data, args.id_dok_aplikasi, args.input.name,
                                  sertakan_gambar=not args.tanpa_gambar)
    except (OSError, json.JSONDecodeError, TransformError) as exc:
        print(f"Gagal: {exc}", file=sys.stderr)
        return 1

    out = args.output or Path(__file__).resolve().parent.parent / "output" / (
        args.input.name.removesuffix(".json").removesuffix(".findings") + ".siitsa.json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    r = result["ringkasan"]
    print(f"[{result['sumber']['format_label']}] "
          f"{r['jumlah_temuan']} temuan, {r['jumlah_langkah_poc']} langkah POC, "
          f"{r['jumlah_gambar_poc']} gambar POC, {r['jumlah_bukti_gambar']} bukti gambar, "
          f"{r['jumlah_peringatan']} peringatan -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
