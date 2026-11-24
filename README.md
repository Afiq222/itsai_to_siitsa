# SIITSA Transformer

Mengubah file JSON temuan **ITS AI** menjadi JSON berformat temuan **SIITSA**:

- 1 finding → 1 body `temuan_itsa` (14 key, sama persis dengan form SIITSA)
- 1 langkah `reproSteps` → 1 body `langkah_poc` (`id_temuan`, `poc`)

Hanya konversi file: tidak memakai AI, tidak terhubung ke ITS AI maupun SIITSA, dan tidak ada server.
Teks dipindahkan apa adanya dari ITS AI.

## Menjalankan

```powershell
cd transformer
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m siitsa_transformer "E:\New folder\response2.json" --id-dok-aplikasi 2
```

Hasil: `transformer/output/<nama>.siitsa.json` (ubah dengan `-o file.json`). Opsi lain: `--tanpa-gambar`
mengabaikan screenshot. Ringkasan jumlah temuan, langkah POC, gambar, dan peringatan dicetak di terminal.
Folder `output/` tidak ikut ke git karena berisi data hasil pentest.

Tes (dari folder `transformer`): `.venv\Scripts\python.exe -m unittest discover -s tests`

## Struktur

```
transformer/
  siitsa_transformer/
    normalize.py   baca & seragamkan 2 format ITS AI, hitung skor CVSS dari vektor, ambil screenshot
    transform.py   label severity + rakit temuan_itsa, langkah_poc, peringatan, urutan, ringkasan
    __main__.py    CLI
  tests/           tes unit
  requirements.txt
```

## Format input (dideteksi otomatis)

| Format | Ciri | Gambar |
|---|---|---|
| ekspor `*.findings.json` (`vacti.findings/v1`) | finding punya `narrative`, `affected`, `evidence` | screenshot dari `evidence[]` ikut diproses |
| JSON API engagement (mis. `response2.json`) | `engagement.id` + finding punya `location`, `locales` (teks `...Id` diutamakan) | tidak ada |

## Format output

```json
{
  "format": "siitsa.temuan-import/v1",
  "sumber": { "file": "...", "format_input": "...", "engagement_id": "...", "engagement": "..." },
  "id_dok_aplikasi": 2,
  "ringkasan": { "jumlah_temuan": 11, "jumlah_langkah_poc": 52, "per_severity": {...}, "jumlah_peringatan": 22 },
  "temuan": [
    {
      "no": 1, "ref": "F-01", "findingClass": "sqli", "status_ai": "...",
      "temuan_itsa": { "id_dok_aplikasi": 2, "id_kamus_kerentanan": null, "subjudul": "...", "perban4": "",
                       "owasptop10": "", "lokasi": "...", "deskripsi_khusus": "...", "dampak_khusus": "...",
                       "rekom_khusus": "...", "cvss": "9.3", "cvss_string": "CVSS:4.0/...", "severity": "Critical",
                       "method": "GET", "status": "Open" },
      "langkah_poc": [ { "id_temuan": null, "poc": "...", "gambar_poc": null } ],
      "bukti_gambar": [ { "nama_file": "F-02-bukti-1.png", "mime": "image/png", "keterangan": "...", "base64": "..." } ],
      "peringatan": [ "..." ]
    }
  ]
}
```

Urutan langkah POC = urutan array (tidak ada field nomor langkah). `id_temuan` diisi dengan id temuan
yang dibuat SIITSA. Gambar (`gambar_poc`, base64) di SIITSA di-upload terpisah sebagai file.

Gambar (format findings.json): screenshot berketerangan "step i/n" dipasang ke langkah ke-i; sisanya masuk
`bukti_gambar[]` dengan peringatan agar validator memilih langkahnya.

## Pemetaan field

| SIITSA | Dari ITS AI |
|---|---|
| `subjudul` | `title` |
| `perban4`, `owasptop10`, `id_kamus_kerentanan` | selalu kosong (`""`, `""`, `null`): tidak ada di data ITS AI, diisi validator di SIITSA |
| `lokasi`, `method` | `affected.url` (+ parameter) dan `affected.method`, atau `location` "METHOD url (param x)" dipecah |
| `deskripsi_khusus` | `description` (+ `Asumsi: ...` jika ada) |
| `dampak_khusus` | `businessImpact` / `impact`, tanpa paragraf baku asumsi CVSS |
| `rekom_khusus` | `remediation` |
| `cvss` / `cvss_string` | `cvssScore`, atau dihitung dari vektor (library `cvss`, CVSS 3.x/4.0) / vektor |
| `severity` | selalu dari ITS AI (`Critical/High/Medium/Low/Info`); beda dengan rating CVSS dicatat di `peringatan` |
| `status` | selalu `Open`; status validasi AI disimpan di `status_ai`, selain `accepted` diberi peringatan |
| `id_dok_aplikasi` | dari `--id-dok-aplikasi` (integer); `engagement.id` hanya dicatat di `sumber.engagement_id` |
| `langkah_poc[].poc` | `reproSteps`, dipecah per baris |

Aturan pecah `reproSteps`: setiap baris = satu langkah, nomor di awal baris dibuang. Jika teks bernomor,
baris tanpa nomor (mis. perintah `curl` di bawah langkah 3) digabung ke langkah sebelumnya.

Nilai yang diterima form SIITSA (acuan, dibaca 2026-11-23): `severity` Critical/High/Medium/Low/Info,
`status` Open/Close, `perban4` 13 label `a. autentikasi` … `m. keamanan konfigurasi`,
`owasptop10` teks bebas seperti `A01:2021`, `id_dok_aplikasi` integer.
