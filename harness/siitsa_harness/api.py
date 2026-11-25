"""Backend harness: uvicorn siitsa_harness.api:app --port 8200

  GET    /                                   UI review
  GET    /api/status                         apakah AI lokal sudah dikonfigurasi
  GET    /api/jobs                           daftar pekerjaan
  POST   /api/jobs                           upload hasil transformer / JSON ITS AI (multipart: file, id_dok_aplikasi)
  GET    /api/jobs/{id}                      ringkasan + daftar temuan
  DELETE /api/jobs/{id}                      hapus pekerjaan
  POST   /api/jobs/{id}/proses               proses AI semua temuan yang belum diproses (latar belakang)
  GET    /api/jobs/{id}/temuan/{no}          detail satu temuan (asli, AI, hasil)
  PUT    /api/jobs/{id}/temuan/{no}          simpan editan validator
  POST   /api/jobs/{id}/temuan/{no}/aksi     setujui | batal_setujui | kembalikan_asli
  POST   /api/jobs/{id}/temuan/{no}/proses   proses ulang AI satu temuan (tanpa cache)
  GET    /api/jobs/{id}/ekspor               unduh hasil akhir (hanya yang disetujui)
"""

from __future__ import annotations

import re
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Literal

from fastapi import Body, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response

from .config import Settings, load_settings
from .ekspor import ekspor
from .llm import ChatFn, LlmError, make_chat
from .masukan import MasukanError, baca_bytes, ke_format_siitsa
from .proses import proses_item
from .prompt import KAMUS, PERBAN4
from .store import Store, ringkas_job

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
_OWASP = re.compile(r"^A(0[1-9]|10):\d{4}$")

settings: Settings = load_settings()
store = Store(settings.data_dir)
# Bisa diganti di tes dengan AI palsu.
chat_factory: Callable[[Settings], ChatFn] = make_chat

_berjalan: set[str] = set()
_berjalan_lock = threading.Lock()

@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Server baru mulai: tidak ada proses AI yang berjalan, jadi status "diproses" yang tersisa
    # adalah sisa proses yang terputus. Reset supaya pekerjaan tidak terkunci selamanya.
    store.pulihkan_macet()
    yield


app = FastAPI(title="SIITSA Harness AI", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan)


# ---------------------------------------------------------------- bantuan

def _muat(job_id: str) -> dict[str, Any]:
    try:
        return store.muat(job_id)
    except KeyError:
        raise HTTPException(404, "Pekerjaan tidak ditemukan.") from None


def _cari(job: dict[str, Any], no: int) -> dict[str, Any]:
    for it in job["temuan"]:
        if it["no"] == no:
            return it
    raise HTTPException(404, f"Temuan nomor {no} tidak ada.")


def _ringkas_temuan(it: dict[str, Any]) -> dict[str, Any]:
    return {
        "no": it["no"], "ref": it["ref"], "severity": it["temuan_itsa"].get("severity"),
        "subjudul": it["hasil"]["subjudul"], "status": it["status"], "status_ai": it["status_ai"],
        "kemungkinan_duplikat": it["kemungkinan_duplikat"], "ada_catatan": bool(it["catatan_ai"] or it["error_ai"]),
        "kategori_sumber": it["kategori_sumber"],
    }


def _sumber_kategori(it: dict[str, Any], kunci: str, nilai: Any) -> str:
    if nilai in ("", None):
        return "kosong"
    ai = (it.get("ai") or {}).get("rekomendasi", {}).get(kunci, {})
    return "rekomendasi_ai" if ai.get("nilai") == nilai else "validator"


# ---------------------------------------------------------------- proses latar belakang

def _jalankan(job_id: str, nos: list[int], pakai_cache: bool) -> None:
    try:
        chat = chat_factory(settings)
        def mulai(job):
            job.update(status="diproses", error=None, pesan=None, progres={"selesai": 0, "total": len(nos)})
            for it in job["temuan"]:
                if it["no"] in nos:
                    it["status_sebelum"] = it["status"]
                    it["status"] = "diproses"
        store.ubah(job_id, mulai)

        for i, no in enumerate(nos, start=1):
            item = _cari(store.muat(job_id), no)
            try:
                proses_item(item, chat, settings.llm_model, settings.data_dir / "cache",
                            settings.max_percobaan, pakai_cache)
            except LlmError as exc:
                pesan = str(exc)
                def gagal(job):
                    job["error"] = pesan
                    for it in job["temuan"]:
                        if it["status"] == "diproses":
                            it["status"] = it.pop("status_sebelum", "belum_diproses")
                            if it["no"] == no:
                                it["error_ai"] = pesan
                store.ubah(job_id, gagal)
                return
            def simpan(job, item=item, i=i):
                for k, it in enumerate(job["temuan"]):
                    if it["no"] == item["no"]:
                        item.pop("status_sebelum", None)
                        job["temuan"][k] = item
                job["progres"]["selesai"] = i
            store.ubah(job_id, simpan)
    except LlmError as exc:
        store.ubah(job_id, lambda job: job.update(error=str(exc)))
    finally:
        def selesai(job):
            job["status"] = "selesai" if not job.get("error") else "gagal"
            for it in job["temuan"]:
                if it["status"] == "diproses":
                    it["status"] = it.pop("status_sebelum", "belum_diproses")
        try:
            store.ubah(job_id, selesai)
        finally:
            with _berjalan_lock:
                _berjalan.discard(job_id)


def _mulai_proses(job_id: str, nos: list[int], pakai_cache: bool) -> None:
    if not settings.ai_siap:
        raise HTTPException(400, "AI belum dikonfigurasi: isi LLM_BASE_URL dan LLM_MODEL di harness/.env, lalu jalankan ulang server.")
    with _berjalan_lock:
        if job_id in _berjalan:
            raise HTTPException(409, "Pekerjaan ini sedang diproses.")
        _berjalan.add(job_id)
    threading.Thread(target=_jalankan, args=(job_id, nos, pakai_cache), daemon=True).start()


# ---------------------------------------------------------------- endpoint

@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/api/status")
def status() -> dict[str, Any]:
    return {
        "ai_siap": settings.ai_siap,
        "model": settings.llm_model,
        "pilihan": {"perban4": list(PERBAN4.values()), "kamus": {str(k): v for k, v in KAMUS.items()}},
    }


@app.get("/api/jobs")
def daftar_job() -> list[dict[str, Any]]:
    return store.daftar()


@app.post("/api/jobs")
async def buat_job(file: UploadFile = File(...), id_dok_aplikasi: int | None = Form(None)) -> dict[str, Any]:
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File terlalu besar (maks 50 MB).")
    try:
        dok = ke_format_siitsa(baca_bytes(raw), file.filename, id_dok_aplikasi)
    except MasukanError as exc:
        raise HTTPException(422, str(exc)) from exc
    return ringkas_job(store.buat(dok, file.filename))


@app.get("/api/jobs/{job_id}")
def lihat_job(job_id: str) -> dict[str, Any]:
    job = _muat(job_id)
    return {**ringkas_job(job), "temuan": [_ringkas_temuan(it) for it in job["temuan"]]}


@app.delete("/api/jobs/{job_id}")
def hapus_job(job_id: str) -> dict[str, str]:
    _muat(job_id)
    with _berjalan_lock:
        if job_id in _berjalan:
            raise HTTPException(409, "Pekerjaan ini sedang diproses.")
    store._path(job_id).unlink()
    return {"status": "dihapus"}


@app.post("/api/jobs/{job_id}/proses")
def proses_job(job_id: str) -> dict[str, Any]:
    job = _muat(job_id)
    nos = [it["no"] for it in job["temuan"] if it["status"] == "belum_diproses"]
    if not nos:
        raise HTTPException(400, "Tidak ada temuan yang belum diproses.")
    _mulai_proses(job_id, nos, pakai_cache=True)
    return {"status": "dimulai", "jumlah": len(nos)}


@app.get("/api/jobs/{job_id}/temuan/{no}")
def lihat_temuan(job_id: str, no: int) -> dict[str, Any]:
    return _cari(_muat(job_id), no)


@app.put("/api/jobs/{job_id}/temuan/{no}")
def simpan_temuan(job_id: str, no: int, hasil: dict[str, Any] = Body(..., embed=True)) -> dict[str, Any]:
    def ubah(job):
        it = _cari(job, no)
        if it["status"] == "diproses":
            raise HTTPException(409, "Temuan ini sedang diproses AI.")
        baru = dict(it["hasil"])
        for k in ("subjudul", "deskripsi_khusus", "dampak_khusus", "rekom_khusus"):
            if k in hasil:
                baru[k] = str(hasil[k] or "").strip()
        if "langkah_poc" in hasil:
            poc = hasil["langkah_poc"]
            if not isinstance(poc, list) or len(poc) != len(it["asli"]["langkah_poc"]):
                raise HTTPException(422, "Jumlah langkah POC harus sama dengan aslinya.")
            baru["langkah_poc"] = [str(p or "").strip() for p in poc]
        if "perban4" in hasil:
            v = str(hasil["perban4"] or "")
            if v and v not in PERBAN4.values():
                raise HTTPException(422, "perban4 harus salah satu label resmi (a. ... sampai m. ...).")
            baru["perban4"] = v
        if "owasptop10" in hasil:
            v = str(hasil["owasptop10"] or "").strip().upper()
            if v and not _OWASP.match(v):
                raise HTTPException(422, "owasptop10 harus berformat A01:2021 sampai A10:2021.")
            baru["owasptop10"] = v
        if "id_kamus_kerentanan" in hasil:
            v = hasil["id_kamus_kerentanan"]
            v = None if v in (None, "") else int(v)
            if v is not None and v not in KAMUS:
                raise HTTPException(422, "id_kamus_kerentanan harus 1 sampai 10 atau kosong.")
            baru["id_kamus_kerentanan"] = v
        it["hasil"] = baru
        for k in ("perban4", "owasptop10", "id_kamus_kerentanan"):
            it["kategori_sumber"][k] = _sumber_kategori(it, k, baru[k])
        if it["status"] == "disetujui":
            it["status"] = "draf"  # diedit lagi: perlu disetujui ulang
    _muat(job_id)
    return _cari(store.ubah(job_id, ubah), no)


@app.post("/api/jobs/{job_id}/temuan/{no}/aksi")
def aksi_temuan(job_id: str, no: int,
                aksi: Literal["setujui", "batal_setujui", "kembalikan_asli"] = Body(..., embed=True)) -> dict[str, Any]:
    def ubah(job):
        it = _cari(job, no)
        if it["status"] == "diproses":
            raise HTTPException(409, "Temuan ini sedang diproses AI.")
        if aksi == "setujui":
            it["status"] = "disetujui"
        elif aksi == "batal_setujui":
            it["status"] = "draf"
        else:
            for k in ("subjudul", "deskripsi_khusus", "dampak_khusus", "rekom_khusus"):
                it["hasil"][k] = it["asli"][k]
            it["hasil"]["langkah_poc"] = list(it["asli"]["langkah_poc"])
            it["status"] = "draf"
    _muat(job_id)
    return _cari(store.ubah(job_id, ubah), no)


@app.post("/api/jobs/{job_id}/temuan/{no}/proses")
def proses_ulang_temuan(job_id: str, no: int) -> dict[str, Any]:
    _cari(_muat(job_id), no)
    _mulai_proses(job_id, [no], pakai_cache=False)
    return {"status": "dimulai", "jumlah": 1}


@app.get("/api/jobs/{job_id}/ekspor")
def ekspor_job(job_id: str) -> JSONResponse:
    job = _muat(job_id)
    hasil = ekspor(job, settings.llm_model)
    if not hasil["temuan"]:
        raise HTTPException(400, "Belum ada temuan yang disetujui.")
    nama = (job["nama_file"] or "hasil").removesuffix(".json").removesuffix(".siitsa").removesuffix(".findings")
    return JSONResponse(hasil, headers={"Content-Disposition": f'attachment; filename="{nama}.final.json"'})
