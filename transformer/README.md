# SIITSA Transformer

Mengubah file JSON temuan **ITS AI** menjadi JSON berformat temuan **SIITSA**:

- 1 finding → 1 body `temuan_itsa` (14 key, sama persis dengan body `POST /api/temuan-itsa` SIITSA)
- 1 langkah `reproSteps` → 1 body `langkah_poc` (`id_temuan`, `poc`) untuk `POST /api/langkah-poc`

Murni konversi file: **tidak memakai AI**, tidak terhubung ke ITS AI maupun SIITSA, dan tidak ada server.
Teks dipindahkan apa adanya dari ITS AI.

## Instalasi (sekali saja)

Butuh Python 3.10 ke atas. Semua perintah dijalankan dari folder `transformer` ini:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Satu-satunya dependensi adalah `cvss` (menghitung skor CVSS 3.x/4.0 dari vektor).

## Menjalankan

```powershell
.venv\Scripts\python.exe -m siitsa_transformer "D:\data\response3.json" --id-dok-aplikasi 2
```

Contoh keluaran di terminal:

```
[JSON tanpa gambar] 30 temuan, 129 langkah POC, 0 gambar POC, 0 bukti gambar, 46 peringatan -> ...\transformer\output\response3.siitsa.json
```

| Opsi | Arti |
|---|---|
| `input` | file JSON ITS AI; formatnya dideteksi otomatis. File ber-BOM (hasil simpan Notepad) juga diterima |
| `-o`, `--output` | lokasi file hasil (default `output/<nama>.siitsa.json`) |
| `--id-dok-aplikasi` | angka `id_dok_aplikasi` dokumen aplikasi di SIITSA (boleh dikosongkan, hasilnya `null`) |
| `--tanpa-gambar` | abaikan screenshot evidence, file hasil jadi jauh lebih kecil |

Kalau gagal (file tidak ada, bukan JSON, atau bukan format ITS AI), CLI mencetak `Gagal: ...` dan tidak membuat file.

Folder `output/` tidak ikut ke git karena berisi data hasil pentest.

## Masking

Alur: file ITS AI → `transform_report()` (format SIITSA) → `mask_report()` (masking). Tanpa AI, hanya regex.
Data sensitif diganti label: `https://[DOMAIN]/api` (path tetap), `[IP]`, `[NIK]`, `[NIP]`, `[TELEPON]`,
`[EMAIL]`, `[NAMA]`, `[PASSWORD]`, `[USERNAME]`, `[TOKEN]`, `[COOKIE]`, `[JWT]`. Payload serangan dan
placeholder ITS AI (`<JWT>`) tidak disentuh. Aturan ada di `MASK_RULES` (`masking.py`); kasus baru
ditambahkan sebagai satu `assert` di `tests/test_masking.py`.

```powershell
.venv\Scripts\python.exe -m pip install pytest
.venv\Scripts\python.exe -m pytest tests
```

## Struktur

```
transformer/
  siitsa_transformer/
    normalize.py   baca & seragamkan 2 format ITS AI, hitung skor CVSS dari vektor, ambil screenshot
    masking.py     regex masking kredensial & data pribadi (payload POC tidak disentuh)
    transform.py   label severity + rakit temuan_itsa, langkah_poc, peringatan, urutan, ringkasan
    __main__.py    CLI
  tests/           tes masking (pytest)
  requirements.txt
```

## Format input (dideteksi otomatis)

| Label di terminal | Ciri | Gambar |
|---|---|---|
| `JSON dengan gambar` | ekspor `*.findings.json` (`vacti.findings/v1`): finding punya `narrative`, `affected`, `evidence` | screenshot dari `evidence[]` ikut diproses |
| `JSON tanpa gambar` | JSON API engagement: `engagement.id` + finding punya `location`, `locales` (teks `...Id` diutamakan) | tidak ada |

## Format output

```json
{
  "format": "siitsa.temuan-import/v1",
  "dibuat": "2026-11-25T03:00:00+00:00",
  "sumber": { "file": "...", "format_input": "api-response", "format_label": "JSON tanpa gambar",
              "engagement_id": "...", "engagement": "..." },
  "id_dok_aplikasi": 2,
  "ringkasan": { "jumlah_temuan": 30, "jumlah_langkah_poc": 129, "jumlah_gambar_poc": 0,
                 "jumlah_bukti_gambar": 0, "per_severity": {"...": 0}, "jumlah_peringatan": 46 },
  "temuan": [
    {
      "no": 1, "ref": "F-01", "findingClass": "sqli", "status_ai": "accepted",
      "temuan_itsa": { "id_dok_aplikasi": 2, "id_kamus_kerentanan": null, "subjudul": "...", "perban4": "",
                       "owasptop10": "", "lokasi": "...", "deskripsi_khusus": "...", "dampak_khusus": "...",
                       "rekom_khusus": "...", "cvss": "9.3", "cvss_string": "CVSS:4.0/...", "severity": "Critical",
                       "method": "GET", "status": "Open" },
      "langkah_poc": [ { "id_temuan": null, "poc": "...", "gambarpoc": null } ],
      "bukti_gambar": [ { "nama_file": "F-01-bukti-1.png", "mime": "image/png", "keterangan": "...", "base64": "..." } ],
      "peringatan": [ "..." ]
    }
  ]
}
```

- Temuan diurutkan dari severity tertinggi (Critical → Info) lalu diberi nomor `no`.
- Urutan langkah POC = urutan array (tidak ada field nomor langkah).
- `id_temuan` masih `null`; isi dengan id temuan yang dikembalikan SIITSA setelah `temuan_itsa` dibuat.
- `gambarpoc` berisi `{nama_file, mime, keterangan, base64}` atau `null`. Di SIITSA gambar di-upload terpisah
  sebagai file: `POST /api/langkah-poc/{id}/gambarpoc` (multipart, field `gambarpoc`).
- Screenshot berketerangan "step i/n" dipasang ke langkah ke-i; sisanya masuk `bukti_gambar[]` dengan
  peringatan agar validator memilih langkahnya sendiri.
- `peringatan[]` berisi hal yang perlu dicek validator, misalnya severity beda dengan rating CVSS,
  status AI bukan `accepted`, vektor CVSS kosong, atau temuan masih kandidat (belum teruji).

## Pemetaan field

| SIITSA | Dari ITS AI |
|---|---|
| `subjudul` | `title` |
| `perban4`, `owasptop10`, `id_kamus_kerentanan` | selalu kosong (`""`, `""`, `null`): tidak ada di data ITS AI, diisi validator di SIITSA |
| `lokasi`, `method` | `affected.url` (+ parameter) dan `affected.method`, atau `location` "METHOD url (param x)" dipecah |
| `deskripsi_khusus` | `description` (+ `Asumsi: ...` jika ada) |
| `dampak_khusus` | `businessImpact` / `impact`, tanpa paragraf baku asumsi CVSS |
| `rekom_khusus` | `remediation` |
| `cvss` / `cvss_string` | `cvssScore`, atau dihitung dari vektor (CVSS 3.x/4.0) / vektor |
| `severity` | selalu dari ITS AI (`Critical/High/Medium/Low/Info`); beda dengan rating CVSS dicatat di `peringatan` |
| `status` | selalu `Open`; status validasi AI disimpan di `status_ai` |
| `id_dok_aplikasi` | dari `--id-dok-aplikasi` (integer); `engagement.id` hanya dicatat di `sumber.engagement_id` |
| `langkah_poc[].poc` | `reproSteps`, dipecah per baris |

Aturan pecah `reproSteps`: setiap baris = satu langkah, nomor di awal baris dibuang. Jika teks bernomor,
baris tanpa nomor (mis. perintah `curl` di bawah langkah 3) digabung ke langkah sebelumnya.

Nilai yang diterima form SIITSA (acuan, dibaca 2026-11-23): `severity` Critical/High/Medium/Low/Info,
`status` Open/Close, `perban4` 13 label `a. autentikasi` … `m. keamanan konfigurasi`,
`owasptop10` teks bebas seperti `A01:2021`, `id_dok_aplikasi` integer.
