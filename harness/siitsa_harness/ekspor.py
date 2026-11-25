"""Ekspor hasil akhir: hanya temuan yang disetujui validator, dalam format temuan SIITSA."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .masukan import FORMAT_SIITSA
from .prompt import PROMPT_VERSION

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def ekspor(job: dict[str, Any], model: str = "") -> dict[str, Any]:
    temuan = []
    for it in job["temuan"]:
        if it["status"] != "disetujui":
            continue
        h = it["hasil"]
        body = dict(it["temuan_itsa"])
        body.update({
            "subjudul": h["subjudul"],
            "deskripsi_khusus": h["deskripsi_khusus"],
            "dampak_khusus": h["dampak_khusus"],
            "rekom_khusus": h["rekom_khusus"],
            "perban4": h["perban4"] or "",
            "owasptop10": h["owasptop10"] or "",
            "id_kamus_kerentanan": h["id_kamus_kerentanan"],
        })
        asli_poc = it["langkah_poc_asli"]
        langkah = [
            {"id_temuan": None, "poc": text,
             "gambarpoc": asli_poc[i].get("gambarpoc") if i < len(asli_poc) else None}
            for i, text in enumerate(h["langkah_poc"])
        ]
        temuan.append({
            "ref": it["ref"],
            "findingClass": it["findingClass"],
            "status_ai": it["status_ai"],
            "temuan_itsa": body,
            "langkah_poc": langkah,
            "bukti_gambar": it.get("bukti_gambar", []),
            # Sumber nilai kategori: "rekomendasi_ai" (belum diubah validator), "validator", atau "kosong".
            "kategori_sumber": it["kategori_sumber"],
        })

    temuan.sort(key=lambda t: SEVERITY_ORDER.index(t["temuan_itsa"]["severity"])
                if t["temuan_itsa"]["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER))
    temuan = [{"no": i, **t} for i, t in enumerate(temuan, start=1)]
    per_severity = {s: 0 for s in SEVERITY_ORDER}
    for t in temuan:
        per_severity[t["temuan_itsa"]["severity"]] = per_severity.get(t["temuan_itsa"]["severity"], 0) + 1

    return {
        "format": FORMAT_SIITSA,
        "dibuat": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sumber": {**(job.get("sumber") or {}), "harness": {"job": job["id"], "model": model, "prompt": PROMPT_VERSION}},
        "id_dok_aplikasi": job.get("id_dok_aplikasi"),
        "ringkasan": {
            "jumlah_temuan": len(temuan),
            "jumlah_langkah_poc": sum(len(t["langkah_poc"]) for t in temuan),
            "per_severity": per_severity,
            "tidak_diekspor": len(job["temuan"]) - len(temuan),
        },
        "temuan": temuan,
    }
