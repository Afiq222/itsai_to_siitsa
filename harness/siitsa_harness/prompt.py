"""Instruksi (prompt) untuk AI dan pilihan kategori yang sah."""

from __future__ import annotations

import json
from typing import Any

PROMPT_VERSION = "v1"

PERBAN4 = {
    "a": "a. autentikasi",
    "b": "b. manajemen sesi",
    "c": "c. persyaratan kontrol akses",
    "d": "d. validasi input",
    "e": "e. kriptografi pada verifikasi statis",
    "f": "f. penanganan eror dan pencatatan log",
    "g": "g. proteksi data",
    "h": "h. keamanan komunikasi",
    "i": "i. pengendalian kode berbahaya",
    "j": "j. logika bisnis",
    "k": "k. file",
    "l": "l. keamanan API dan web service",
    "m": "m. keamanan konfigurasi",
}

OWASP = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}
OWASP_TAHUN = "2021"  # form SIITSA memakai contoh "A01:2021"

# Kamus kerentanan SIITSA (dibaca dari halaman kamus SIITSA, 2026-11-23).
KAMUS = {
    1: "SQL Injection",
    2: "Cross-Site Scripting (XSS)",
    3: "Cross-Site Request Forgery (CSRF)",
    4: "Brute Force Login",
    5: "Insecure Direct Object Reference (IDOR)",
    6: "Directory Traversal",
    7: "Ransomware Infection",
    8: "Misconfigured Firewall",
    9: "Weak Password Policy",
    10: "Unpatched Software Vulnerabilities",
}

# Batas panjang hasil AI (karakter).
BATAS = {"subjudul": 100, "poin": 220, "jumlah_poin": 5}

SYSTEM_PROMPT = f"""Kamu membantu validator menyusun laporan uji keamanan aplikasi (ITSA) untuk instansi pemerintah.
Tugasmu: menulis ulang SATU temuan agar singkat, sederhana, dan langsung ke inti, dalam Bahasa Indonesia baku.

Aturan tulisan:
- Semua teks dalam Bahasa Indonesia. Istilah teknis baku (SQL Injection, XSS, IDOR, endpoint, token, API) boleh tetap.
- Pembaca bukan ahli teknis: hindari jargon yang tidak perlu, jelaskan dengan kalimat pendek.
- JANGAN menambah fakta yang tidak ada di data temuan. Angka, nama endpoint, dan nama data harus sesuai sumber.
- Jangan menulis nama orang, NIK, NIP, nomor HP, email, atau kata sandi dari data temuan ke subjudul/deskripsi/dampak/rekomendasi.
- "subjudul": satu frasa to the point, maksimal {BATAS['subjudul']} karakter. Pola: <jenis kerentanan> pada <fitur/endpoint singkat>.
- "deskripsi", "dampak", "rekomendasi": masing-masing daftar 1 sampai {BATAS['jumlah_poin']} poin, tiap poin satu kalimat pendek (maksimal {BATAS['poin']} karakter), tanpa tanda "-" atau nomor di depannya.
- Jika dampak di data kosong, susun dampak dari deskripsi tanpa menambah fakta baru.
- "langkah_poc": jumlahnya HARUS sama persis dengan langkah asli dan urutannya sama. Ringkas hanya langkah yang bertele-tele;
  langkah yang sudah singkat salin apa adanya (boleh diterjemahkan). URL, perintah (curl dsb.), payload, nama parameter,
  kode status HTTP, dan teks di dalam tanda backtick (`...`) HARUS disalin persis tanpa diubah.

Kategori (berikan rekomendasi terbaik beserta alasan singkat satu kalimat):
- "perban4": satu huruf kategori Peraturan BSSN Nomor 4 Tahun 2021 Pasal 26:
{chr(10).join(f'  {k} = {v[3:]}' for k, v in PERBAN4.items())}
- "owasptop10": satu kode OWASP Top 10 {OWASP_TAHUN}:
{chr(10).join(f'  {k} = {v}' for k, v in OWASP.items())}
- "id_kamus_kerentanan": angka dari kamus berikut, atau null bila tidak ada yang benar-benar cocok:
{chr(10).join(f'  {k} = {v}' for k, v in KAMUS.items())}

Jawab HANYA dengan satu objek JSON berikut, tanpa teks lain:
{{"subjudul": "...", "deskripsi": ["..."], "dampak": ["..."], "rekomendasi": ["..."], "langkah_poc": ["..."],
 "perban4": "d", "alasan_perban4": "...", "owasptop10": "A03", "alasan_owasp": "...",
 "id_kamus_kerentanan": 1, "alasan_kamus": "..."}}"""


def user_prompt(asli: dict[str, Any], konteks: dict[str, Any]) -> str:
    data = {
        "jenis_temuan_its_ai": konteks.get("findingClass", ""),
        "severity": konteks.get("severity", ""),
        "method": konteks.get("method", ""),
        "lokasi": konteks.get("lokasi", ""),
        "subjudul": asli["subjudul"],
        "deskripsi": asli["deskripsi_khusus"],
        "dampak": asli["dampak_khusus"],
        "rekomendasi": asli["rekom_khusus"],
        "langkah_poc": asli["langkah_poc"],
    }
    return (
        f"Data temuan (jumlah langkah_poc: {len(asli['langkah_poc'])}):\n"
        + json.dumps(data, ensure_ascii=False, indent=1)
    )


def retry_prompt(masalah: list[str]) -> str:
    return (
        "Jawabanmu belum memenuhi aturan:\n- " + "\n- ".join(masalah)
        + "\nPerbaiki dan kirim ulang SELURUH objek JSON sesuai format."
    )
