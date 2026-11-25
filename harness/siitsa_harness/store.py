"""Penyimpanan pekerjaan (job) sebagai file JSON di data/jobs/<id>.json.

Satu job = satu file yang di-upload. Setiap temuan menyimpan teks asli, versi AI, dan versi
akhir yang bisa diedit validator ("hasil").
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUS_TEMUAN = ("belum_diproses", "diproses", "draf", "perlu_cek", "disetujui")


def _sekarang() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _poc_teks(t: dict[str, Any]) -> list[str]:
    return [p.get("poc", "") for p in t.get("langkah_poc", [])]


def item_baru(t: dict[str, Any]) -> dict[str, Any]:
    body = t["temuan_itsa"]
    asli = {
        "subjudul": body.get("subjudul", ""),
        "deskripsi_khusus": body.get("deskripsi_khusus", ""),
        "dampak_khusus": body.get("dampak_khusus", ""),
        "rekom_khusus": body.get("rekom_khusus", ""),
        "langkah_poc": _poc_teks(t),
    }
    return {
        "no": t.get("no"),
        "ref": t.get("ref", ""),
        "findingClass": t.get("findingClass", ""),
        "status_ai": t.get("status_ai", ""),
        "peringatan": t.get("peringatan", []),
        "bukti_gambar": t.get("bukti_gambar", []),
        "temuan_itsa": body,
        "langkah_poc_asli": t.get("langkah_poc", []),
        "asli": asli,
        "ai": None,
        "hasil": {
            **{k: v for k, v in asli.items()},
            "langkah_poc": list(asli["langkah_poc"]),
            "perban4": body.get("perban4", ""),
            "owasptop10": body.get("owasptop10", ""),
            "id_kamus_kerentanan": body.get("id_kamus_kerentanan"),
        },
        "kategori_sumber": {"perban4": "kosong", "owasptop10": "kosong", "id_kamus_kerentanan": "kosong"},
        "status": "belum_diproses",
        "catatan_ai": [],
        "error_ai": None,
        "kemungkinan_duplikat": [],
        "diubah": _sekarang(),
    }


def tandai_duplikat(items: list[dict[str, Any]]) -> None:
    """Temuan dengan method + lokasi sama ditandai kemungkinan duplikat (keputusan tetap di validator)."""
    grup: dict[tuple[str, str], list[int]] = {}
    for it in items:
        key = (it["temuan_itsa"].get("method", ""), it["temuan_itsa"].get("lokasi", ""))
        if key[1]:
            grup.setdefault(key, []).append(it["no"])
    for it in items:
        key = (it["temuan_itsa"].get("method", ""), it["temuan_itsa"].get("lokasi", ""))
        it["kemungkinan_duplikat"] = [n for n in grup.get(key, []) if n != it["no"]]


class Store:
    def __init__(self, data_dir: Path):
        self.dir = Path(data_dir) / "jobs"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _path(self, job_id: str) -> Path:
        if not job_id or not all(c.isalnum() or c == "-" for c in job_id):
            raise KeyError(job_id)
        return self.dir / f"{job_id}.json"

    def buat(self, dok: dict[str, Any], nama_file: str | None) -> dict[str, Any]:
        items = [item_baru(t) for t in dok["temuan"]]
        tandai_duplikat(items)
        job = {
            "id": uuid.uuid4().hex[:12],
            "dibuat": _sekarang(),
            "nama_file": nama_file or "",
            "sumber": dok.get("sumber", {}),
            "id_dok_aplikasi": dok.get("id_dok_aplikasi"),
            "status": "siap",
            "progres": {"selesai": 0, "total": 0},
            "error": None,
            "temuan": items,
        }
        self.simpan(job)
        return job

    def simpan(self, job: dict[str, Any]) -> None:
        with self._lock:
            path = self._path(job["id"])
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(job, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)

    def muat(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            path = self._path(job_id)
            if not path.is_file():
                raise KeyError(job_id)
            return json.loads(path.read_text(encoding="utf-8"))

    def ubah(self, job_id: str, fn) -> dict[str, Any]:
        """Muat, ubah lewat fn(job), lalu simpan dalam satu kunci (aman dari proses latar belakang)."""
        with self._lock:
            job = self.muat(job_id)
            fn(job)
            self.simpan(job)
            return job

    def daftar(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                job = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            out.append(ringkas_job(job))
        return out

    def pulihkan_macet(self) -> list[str]:
        """Dipanggil saat server mulai: saat itu belum ada proses AI yang berjalan, jadi status
        "diproses" yang masih tersimpan pasti sisa proses yang terputus (server/laptop mati).

        Temuan "diproses" dikembalikan ke status sebelumnya (atau "belum_diproses"); temuan yang
        sudah selesai tidak disentuh. Pekerjaan diberi status "terhenti" supaya bisa dilanjutkan.
        Mengembalikan id pekerjaan yang dipulihkan.
        """
        dipulihkan = []
        with self._lock:
            for p in self.dir.glob("*.json"):
                try:
                    job = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                macet = [it for it in job.get("temuan", []) if it.get("status") == "diproses"]
                if job.get("status") != "diproses" and not macet:
                    continue
                for it in macet:
                    it["status"] = it.pop("status_sebelum", None) or "belum_diproses"
                job["status"] = "terhenti"
                job["pesan"] = "Proses AI terhenti karena server dimatikan. Klik Proses AI untuk melanjutkan."
                self.simpan(job)
                dipulihkan.append(job["id"])
        return dipulihkan


def ringkas_job(job: dict[str, Any]) -> dict[str, Any]:
    hitung = {s: 0 for s in STATUS_TEMUAN}
    for it in job["temuan"]:
        hitung[it["status"]] = hitung.get(it["status"], 0) + 1
    return {
        "id": job["id"],
        "dibuat": job["dibuat"],
        "nama_file": job["nama_file"],
        "engagement": (job.get("sumber") or {}).get("engagement"),
        "id_dok_aplikasi": job.get("id_dok_aplikasi"),
        "status": job["status"],
        "progres": job["progres"],
        "error": job.get("error"),
        "pesan": job.get("pesan"),
        "jumlah_temuan": len(job["temuan"]),
        "per_status": hitung,
    }
