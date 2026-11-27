from siitsa_transformer.masking import main_domain, mask, target_domains


def test_kredensial_di_mask():
    assert mask("Authorization: Bearer abc.def") == "Authorization: Bearer [TOKEN]"
    assert mask("Cookie: PHPSESSID=abc123; x=1") == "Cookie: [COOKIE]"
    assert mask('{"password": "admin123"}') == '{"password": "[PASSWORD]"}'
    assert mask("GET /api?token=s3cr3t&id=1") == "GET /api?token=[TOKEN]&id=1"
    assert mask("pakai eyJhbGci.eyJzdWIi.sig-123 di header") == "pakai [JWT] di header"


def test_username_dan_nama_di_mask():
    assert mask('{"username":"budi99","user":{"id":1}}') == '{"username":"[USERNAME]","user":{"id":1}}'
    assert mask("login dengan curl -u admin:rahasia https") == "login dengan curl -u [USERNAME]:[PASSWORD] https"
    assert mask("Nama: Budi Santoso, NIP valid") == "Nama: [NAMA], NIP valid"
    assert mask('{"name": "Siti Aminah"}') == '{"name": "[NAMA]"}'
    assert mask("nama_lengkap=Budi&x=1") == "nama_lengkap=[NAMA]&x=1"


def test_data_pribadi_di_mask():
    assert mask("kontak budi.santoso@example.com") == "kontak [EMAIL]"
    assert mask("hp 081234567890") == "hp [TELEPON]"
    assert mask("wa +62 812-3456-7890") == "wa [TELEPON]"
    assert mask("NIK 3201012345670001") == "NIK [NIK]"
    assert mask("NIP 19800101 200501 1 001") == "NIP [NIP]"
    assert mask("server 10.0.0.12:8080 dan 103.142.89.234") == "server [IP]:8080 dan [IP]"


def test_domain_target_path_tetap():
    domains = target_domains(["https://dev1.gorontaloprov.go.id/api/user (parameter: id)", "dev4.gorontaloprov.go.id"])
    assert domains == {"gorontaloprov.go.id"}
    text = "buka https://dev1.gorontaloprov.go.id/api/user lalu cek sso.gorontaloprov.go.id, lihat owasp.org"
    assert mask(text, domains) == "buka https://[DOMAIN]/api/user lalu cek [DOMAIN], lihat owasp.org"
    assert mask("admin@gorontaloprov.go.id", domains) == "[EMAIL]"
    assert main_domain("siapman.lamongankab.go.id") == "lamongankab.go.id"
    assert main_domain("103.142.89.234") is None


def test_payload_tetap_utuh():
    for payload in ["id=1' OR 1=1--", "<script>alert(1)</script>", "../../etc/passwd", "jQuery 1.12.4"]:
        assert mask(payload) == payload


def test_placeholder_dan_curl_tidak_rusak():
    cmd = "curl -H 'Authorization: Bearer <JWT>' -H 'Cookie: sess=abc' 'https://x.test/a'"
    assert mask(cmd) == "curl -H 'Authorization: Bearer <JWT>' -H 'Cookie: [COOKIE]' 'https://x.test/a'"
    assert mask("password=<PASSWORD>") == "password=<PASSWORD>"


def test_alur_transform_lalu_mask():
    from siitsa_transformer import mask_report, transform_report

    data = {"findings": [{
        "id": "F1", "title": "IDOR di dev1.target.go.id", "severity": "High",
        "location": "GET https://dev1.target.go.id/api/user?id=1",
        "description": "Data Nama: Budi Santoso, NIK 3201012345670001 bocor dari sso.target.go.id",
        "reproSteps": "1. curl -u admin:rahasia https://dev1.target.go.id/api/user?id=1",
    }]}
    hasil = transform_report(data)
    # tahap transform belum menyentuh data sensitif
    assert "dev1.target.go.id" in hasil["temuan"][0]["temuan_itsa"]["lokasi"]

    mask_report(hasil)
    ti = hasil["temuan"][0]["temuan_itsa"]
    assert ti["lokasi"] == "https://[DOMAIN]/api/user?id=1"
    assert ti["subjudul"] == "IDOR di [DOMAIN]"
    assert ti["deskripsi_khusus"] == "Data Nama: [NAMA], NIK [NIK] bocor dari [DOMAIN]"
    assert hasil["temuan"][0]["langkah_poc"][0]["poc"] == "curl -u [USERNAME]:[PASSWORD] https://[DOMAIN]/api/user?id=1"


def test_mask_report_tahan_file_tidak_lengkap():
    from siitsa_transformer import mask_report

    rusak = {"temuan": [None, {"temuan_itsa": {"lokasi": 5}}, {"temuan_itsa": {}, "langkah_poc": ["x"]}]}
    assert mask_report(rusak) is rusak
    assert rusak["temuan"][2]["temuan_itsa"] == {}


def test_varian_nama_kunci_rahasia():
    # kata rahasia di posisi mana pun dalam nama kunci tetap tertangkap
    varian = {
        "password_confirmation": "PASSWORD", "passwordConfirmation": "PASSWORD", "confirm_password": "PASSWORD",
        "new_pwd": "PASSWORD", "old_passwd": "PASSWORD", "kata_sandi_baru": "PASSWORD",
        "refresh_token": "TOKEN", "client_secret": "TOKEN", "X-Api-Key": "TOKEN",
    }
    for key, label in varian.items():
        assert mask(f'{{"{key}":"Rahasia!2026"}}') == f'{{"{key}":"[{label}]"}}', key
        assert mask(f"{key}=Rahasia!2026&x=1") == f"{key}=[{label}]&x=1", key


def test_kunci_umum_tidak_berlebihan():
    # id di POC IDOR adalah bukti, jangan di-mask
    for text in ["user_id=5", "login_url=/auth", "User-Agent: Mozilla/5.0", "bypass=1"]:
        assert mask(text) == text, text


def test_password_di_kalimat_bebas():
    assert mask('fixed default password "123456", no lockout') == 'fixed default password "[PASSWORD]", no lockout'
    assert mask("default password 123456, no forced change") == "default password [PASSWORD], no forced change"
    assert mask("login dengan password baru berhasil") == "login dengan password baru berhasil"
