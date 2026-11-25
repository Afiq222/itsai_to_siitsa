# Harness AI

Tahap kedua setelah transformer. Mengambil hasil transformer (`*.siitsa.json`) lalu memakai **AI lokal**
untuk membuat setiap temuan singkat, sederhana, dan seragam dalam Bahasa Indonesia, dan merekomendasikan
kategori. Validator memeriksa dan menyetujui hasilnya lewat UI, lalu mengekspor file akhir untuk SIITSA.

Transformer tidak diubah dan tetap tanpa AI.

```
JSON ITS AI ─► transformer ─► *.siitsa.json ─► harness (AI lokal + review) ─► *.final.json ─► SIITSA
```

## Yang dikerjakan AI per temuan

| Kolom | Hasil |
|---|---|
| `subjudul` | singkat, to the point (maks 100 karakter) |
| `deskripsi_khusus`, `dampak_khusus`, `rekom_khusus` | poin-poin pendek berbahasa Indonesia sederhana (`- ...`) |
| `langkah_poc[].poc` | diringkas hanya bila bertele-tele; jumlah dan urutan langkah tetap |
| `perban4`, `owasptop10`, `id_kamus_kerentanan` | diisi sebagai **rekomendasi AI** beserta alasannya |

Tidak disentuh AI: `cvss`, `cvss_string`, `severity`, `method`, `lokasi`, `status`, `id_dok_aplikasi`, gambar.

## Pengaman (oleh kode)

- Kategori harus nilai sah: 13 label Perban 4, `A01:2021`–`A10:2021`, kamus SIITSA 1–10 atau kosong.
- Langkah POC: URL, isi `` `backtick` ``, baris `curl`, dan angka (≥3 digit) di langkah asli wajib tetap ada.
  Langkah yang kehilangan bagian teknis memakai teks asli.
- Batas panjang subjudul dan poin. Jawaban yang melanggar membuat AI diminta mengulang (bawaan 3 kali);
  bila tetap gagal, bagian itu memakai teks asli dan temuan berstatus **perlu cek**.
- Teks asli selalu disimpan; validator bisa mengembalikannya.
- Hasil AI di-cache per temuan, jadi file yang sama tidak diproses ulang dan hasilnya tetap.
- Temuan dengan method + lokasi sama ditandai **kemungkinan duplikat**.

## Menjalankan

```powershell
cd harness
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m uvicorn siitsa_harness.api:app --port 8200
```

Buka http://127.0.0.1:8200.

AI diatur di `harness/.env` (salin dari `.env.example`). Selama `LLM_BASE_URL` / `LLM_MODEL` kosong,
UI tetap bisa dipakai untuk review dan edit manual, tetapi tombol **Proses AI** nonaktif. Server AI lokal apa
pun yang kompatibel OpenAI bisa dipakai, contoh Ollama: `LLM_BASE_URL=http://127.0.0.1:11434/v1`.

Tes (butuh `pip install -r requirements-dev.txt`): `.venv\Scripts\python.exe -m unittest discover -s tests`

## Cara pakai

1. Upload `*.siitsa.json` dari transformer (JSON mentah ITS AI juga bisa; transformer dijalankan otomatis).
   Isi `id_dok_aplikasi` bila perlu.
2. Klik **Proses AI**. Progres tampil di atas; AI lokal bisa butuh puluhan detik per temuan.
3. Pilih temuan di kiri: bandingkan teks asli dan hasil, edit bila perlu, cek kategori bertanda
   **Rekomendasi AI**, lalu **Simpan & setujui**. Tombol lain: **Kembalikan teks ke asli**, **Proses ulang AI**.
4. Klik **Ekspor disetujui** untuk mengunduh `<nama>.final.json`.

## Format file akhir

Sama dengan output transformer (`temuan_itsa` 14 key, `langkah_poc` berisi `id_temuan`, `poc`, `gambarpoc`),
hanya berisi temuan yang disetujui, ditambah per temuan:

```json
"kategori_sumber": { "perban4": "rekomendasi_ai", "owasptop10": "validator", "id_kamus_kerentanan": "kosong" }
```

`rekomendasi_ai` = nilai dari AI yang belum diubah validator, `validator` = diubah validator, `kosong` = tidak diisi.

## Struktur

```
siitsa_harness/
  config.py    pengaturan dari .env
  llm.py       klien AI lokal (API kompatibel OpenAI, tanpa library tambahan)
  prompt.py    instruksi AI, daftar Perban 4 / OWASP / kamus
  periksa.py   pemeriksaan jawaban AI oleh kode
  proses.py    tanya AI, ulangi bila perlu, cache
  masukan.py   baca upload (hasil transformer atau JSON ITS AI)
  store.py     simpan pekerjaan di data/jobs/
  ekspor.py    file akhir (hanya yang disetujui)
  api.py       backend FastAPI
  static/      UI review
tests/         tes dengan AI palsu
```

Data pekerjaan dan cache tersimpan di `harness/data/` dan tidak ikut ke git (berisi data hasil pentest).
