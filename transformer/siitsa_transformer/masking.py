"""Masking data sensitif di teks temuan ITS AI (regex, deterministik, tanpa AI).

Yang di-mask: domain target (path tetap tampil), NIK, NIP, nomor telepon, nama orang,
password, username, IP, plus token/cookie/email. Payload serangan (SQLi, XSS, dll.)
sengaja TIDAK di-mask karena itu bukti POC yang perlu direproduksi validator.
Nilai diganti label jenisnya, dibungkus kurung siku: https://[DOMAIN]/api, [IP], [NIK], [NIP],
[TELEPON], [EMAIL], [NAMA], password=[PASSWORD], username=[USERNAME], [TOKEN], [COOKIE], [JWT].

Batas regex: nama orang hanya tertangkap kalau ada label/key-nya (Nama: Budi, "name":"Budi",
nama_lengkap=...). Nama di kalimat bebas ("akun milik Budi") tidak bisa dikenali regex.

Menambah aturan: tambahkan satu baris (nama, pola, pengganti) ke MASK_RULES
dan satu contoh di tests/test_masking.py. Urutan penting: aturan dijalankan dari atas.
"""
from __future__ import annotations

import re
from collections.abc import Iterable


def _label_kunci(key: str) -> str:
    """Label pengganti dari nama kunci: password=... -> PASSWORD, username=... -> USERNAME, dst."""
    k = key.lower()
    if re.search(r"pass|pwd|sandi", k):
        return "PASSWORD"
    if re.search(r"secret|token|key|credential", k):
        return "TOKEN"
    last = re.split(r"[_-]", k)[-1]  # kunci lemah selalu diakhiri kata kuncinya: user_nik -> nik
    if last in ("nip", "nik"):
        return last.upper()
    if re.search(r"user|uname|login", last):  # sebelum NAMA: "username" juga mengandung "name"
        return "USERNAME"
    return "NAMA"


def _ganti_nilai(m: re.Match[str], label: str | None = None) -> str:
    """Pengganti key=nilai: kunci tetap, nilai jadi label, kutip pembungkus dipertahankan."""
    value = m.group("val")
    quote = value[0] if value[:1] in "\"'`" else ""
    return f"{m.group('pre')}{quote}[{label or _label_kunci(m.group('key'))}]{quote}"


# Kunci KUAT: rahasia di posisi mana pun dalam nama kunci, jadi varian baru ikut tertangkap:
# password_confirmation, confirmPassword, new_pwd, kata_sandi_baru, refresh_token, client_secret.
_KUAT = (
    r"password|passwd|passcode|passphrase|pwd|sandi|secret|token|api[_-]?key"
    r"|private[_-]?key|access[_-]?key|credential"
)
# Kunci LEMAH: kata umum, hanya kalau jadi akhir nama kunci (boleh berawalan admin_, user_).
# Tidak boleh berakhiran lain supaya user_id / login_url / nik_valid tidak ikut ter-mask
# (id di POC IDOR itu bukti, bukan data sensitif).
_LEMAH = (
    r"pass|user(?:name)?|uname|login"
    r"|nama(?:_lengkap)?|full_?name|first_?name|last_?name|display_?name|nip|nik"
)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"

# Nilai yang diawali "<" (mis. <JWT>, <SESSION>) sudah placeholder dari ITS AI, jadi dilewati.
# Nilai tanpa kutip berhenti di kutip/backtick/spasi supaya perintah curl di POC tidak rusak.
MASK_RULES: list[tuple[str, re.Pattern[str], object]] = [
    ("jwt", re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"), "[JWT]"),
    ("authorization", re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)(?!<)[^\s'\"`]+"), r"\1[TOKEN]"),
    ("cookie", re.compile(r"(?i)((?:set-)?cookie:\s*)(?!<)[^\r\n'\"`]+"), r"\1[COOKIE]"),
    # Nama tanpa kutip setelah label: ambil sampai 5 kata berhuruf kapital (Nama: Budi Santoso).
    (
        "nama berlabel",
        re.compile(r"(?<![\w-])((?i:nama(?:[_ ]lengkap)?|full[_ ]?name|name)\s*[:=]\s*)(?!<)[A-Z][\w.'-]*(?:[ ]+[A-Z][\w.'-]*){0,4}"),
        r"\1[NAMA]",
    ),
    ("json name", re.compile(r"(?P<pre>\"(?P<key>(?i:name))\"\s*:\s*)(?P<val>\"(?!<)[^\"\r\n]*\")"), _ganti_nilai),
    # key=nilai / key: nilai / "key":"nilai"
    (
        "key-value",
        re.compile(
            rf"(?<![\w-])(?P<pre>(?P<key>[\w-]*?(?i:{_KUAT})[\w-]*|(?:[\w-]*[_-])?(?i:{_LEMAH}))[\"']?\s*[:=]\s*)"
            r"(?P<val>\"(?!<)[^\"\r\n]*\"|'(?!<)[^'\r\n]*'|(?![<{\[\"'])[^&\"'`\s,;}]+)"
        ),
        _ganti_nilai,
    ),
    # Password di kalimat bebas: default password "123456", kata sandi adalah `abc`, password 123456.
    (
        "password teks",
        re.compile(
            r"(?P<pre>(?i:\b(?:password|passwd|kata sandi|sandi)\s+(?:default\s+|awal\s+)?(?:is\s+|adalah\s+|=\s*)?))"
            r"(?P<val>\"(?!<)[^\"\r\n]{1,64}\"|'(?!<)[^'\r\n]{1,64}'|`(?!<)[^`\r\n]{1,64}`|\d{4,}\b)"
        ),
        lambda m: _ganti_nilai(m, "PASSWORD"),
    ),
    # Setelah key-value: hasil USERNAME:PASSWORD jangan sampai dibaca lagi sebagai key USERNAME.
    ("curl -u", re.compile(r"((?:^|\s)(?:-u|--user)\s+['\"]?)(?!<)[^\s'\"]+"), r"\1[USERNAME]:[PASSWORD]"),
    ("email",re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]*\w"), "[EMAIL]"),
    # NIP ASN: 18 digit, boleh berspasi (19800101 200501 1 001). Sebelum NIK supaya tidak terpotong.
    ("nip", re.compile(r"(?<!\d)\d{8}[ ]?\d{6}[ ]?\d[ ]?\d{3}(?!\d)"), "[NIP]"),
    # shortcut: 16 digit apa pun dianggap NIK, bisa kena ID panjang; perketat kalau ada false positive.
    ("nik", re.compile(r"(?<!\d)\d{16}(?!\d)"), "[NIK]"),
    ("telepon", re.compile(r"(?<![\d+])(?:\+?62[\s-]?|0)8\d{1,2}[\s-]?\d{3,4}[\s-]?\d{3,5}(?!\d)"), "[TELEPON]"),
    ("ip", re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?![\d]|\.\d)"), "[IP]"),
]

# Second-level domain Indonesia & umum: gorontaloprov.go.id -> domain utama 3 label.
_SLD = {"go", "ac", "co", "or", "web", "sch", "my", "net", "mil", "biz", "ponpes", "desa", "com", "org"}
_HOST = re.compile(r"[a-z]+://([^/\s'\"`:?#()]+)", re.I)
_IP = re.compile(rf"^{_OCTET}(?:\.{_OCTET}){{3}}$")


def main_domain(host: str) -> str | None:
    """dev1.gorontaloprov.go.id -> gorontaloprov.go.id; IP/localhost -> None (IP ditangani aturan ip)."""
    labels = host.lower().strip(".").removeprefix("*.").split(".")
    if len(labels) < 2 or _IP.match(".".join(labels)):
        return None
    n = 3 if len(labels) >= 3 and labels[-2] in _SLD and len(labels[-1]) == 2 else 2
    return ".".join(labels[-n:])


def target_domains(values: Iterable[str]) -> set[str]:
    """Domain utama dari lokasi/scope (URL atau host polos)."""
    found = set()
    for value in values:
        value = (value or "").strip()
        hosts = _HOST.findall(value) if "://" in value else [value.split("/")[0]]
        found.update(d for d in map(main_domain, hosts) if d)
    return found


TEMUAN_FIELDS = ("subjudul", "lokasi", "deskripsi_khusus", "dampak_khusus", "rekom_khusus")


def mask_report(report: dict) -> dict:
    """Tahap setelah transform: mask hasil format SIITSA (in place, juga dikembalikan).

    Domain target diambil dari lokasi semua temuan + scope, lalu dipakai di semua field teks.
    """
    # .get di mana-mana: file *.siitsa.json bisa di-upload user, strukturnya belum tentu lengkap.
    temuan = [t for t in report.get("temuan") or [] if isinstance(t, dict) and isinstance(t.get("temuan_itsa"), dict)]
    sumber = report.get("sumber") if isinstance(report.get("sumber"), dict) else {}
    scope = [s for s in sumber.get("scope") or [] if isinstance(s, str)]
    lokasi = [t["temuan_itsa"].get("lokasi") for t in temuan]
    domains = target_domains([*scope, *(x for x in lokasi if isinstance(x, str))])

    def m(value):
        return mask(value, domains) if isinstance(value, str) else value

    for t in temuan:
        ti = t["temuan_itsa"]
        for key in TEMUAN_FIELDS:
            if key in ti:
                ti[key] = m(ti[key])
        for langkah in t.get("langkah_poc") or []:
            if isinstance(langkah, dict):
                if "poc" in langkah:
                    langkah["poc"] = m(langkah["poc"])
                gambar = langkah.get("gambarpoc")
                if isinstance(gambar, dict) and "keterangan" in gambar:
                    gambar["keterangan"] = m(gambar["keterangan"])
        for gambar in t.get("bukti_gambar") or []:
            if isinstance(gambar, dict) and "keterangan" in gambar:
                gambar["keterangan"] = m(gambar["keterangan"])
    if scope:
        sumber["scope"] = [m(s) for s in scope]
    return report


def mask(text: str, domains: Iterable[str] = ()) -> str:
    """Kembalikan teks dengan data sensitif disamarkan. `domains` = domain utama target."""
    for _name, pattern, repl in MASK_RULES:
        text = pattern.sub(repl, text)
    # Domain terakhir: email admin@target.go.id sudah jadi EMAIL lebih dulu.
    for d in sorted(domains, key=len, reverse=True):
        text = re.sub(rf"(?<![\w.-])(?:[\w-]+\.)*{re.escape(d)}(?![\w-])", "[DOMAIN]", text, flags=re.I)
    return text
