import json
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from siitsa_harness import api
from siitsa_harness.config import Settings
from siitsa_harness.llm import LlmError, make_chat
from siitsa_harness.periksa import parse_json, periksa, token_hilang
from siitsa_harness.proses import proses_item
from siitsa_harness.store import item_baru

try:
    from fastapi.testclient import TestClient
except Exception:  # httpx belum terpasang
    TestClient = None

ASLI = {
    "subjudul": "SQL Injection at GET /apps/api/v2/admin/data-requests/walidata-inbox (param per_page)",
    "deskripsi_khusus": "The parameter is concatenated into a SQL query without parameterisation.",
    "dampak_khusus": "",
    "rekom_khusus": "Use parameterised queries.",
    "langkah_poc": [
        "Target GET https://t.example/x, parameter `per_page` - payload: (detected + confirmed by sqlmap)",
        "Exploitation was confirmed deterministically by sqlmap. Response HTTP 200 with 11,778 rows.",
    ],
}


def jawaban_ai(**over):
    d = {
        "subjudul": "SQL Injection pada endpoint walidata-inbox",
        "deskripsi": ["Parameter per_page tidak disaring sebelum dipakai di query database."],
        "dampak": ["Penyerang dapat membaca isi database."],
        "rekomendasi": ["Gunakan parameterized query.", "Batasi hak akun database."],
        "langkah_poc": [
            "Kirim GET ke https://t.example/x dengan parameter `per_page` (terdeteksi sqlmap).",
            "Eksploitasi dikonfirmasi sqlmap: HTTP 200 dengan 11.778 baris.",
        ],
        "perban4": "d", "alasan_perban4": "Input tidak divalidasi.",
        "owasptop10": "A03", "alasan_owasp": "Injection.",
        "id_kamus_kerentanan": 1, "alasan_kamus": "SQL Injection.",
    }
    d.update(over)
    return json.dumps(d)


def temuan_transformer(no=1, poc=None, lokasi="https://t.example/x (parameter: per_page)"):
    return {
        "no": no, "ref": f"F-0{no}", "findingClass": "sqli", "status_ai": "accepted", "peringatan": [],
        "temuan_itsa": {
            "id_dok_aplikasi": 2, "id_kamus_kerentanan": None, "subjudul": ASLI["subjudul"], "perban4": "",
            "owasptop10": "", "lokasi": lokasi, "deskripsi_khusus": ASLI["deskripsi_khusus"],
            "dampak_khusus": "", "rekom_khusus": ASLI["rekom_khusus"], "cvss": "9.3",
            "cvss_string": "CVSS:4.0/AV:N", "severity": "Critical", "method": "GET", "status": "Open",
        },
        "langkah_poc": [{"id_temuan": None, "poc": p, "gambarpoc": None} for p in (poc or ASLI["langkah_poc"])],
        "bukti_gambar": [],
    }


class PeriksaTest(unittest.TestCase):
    def test_valid_answer_has_no_problem_and_maps_categories(self):
        masalah, hasil, catatan = periksa(parse_json(jawaban_ai()), ASLI)
        self.assertEqual(masalah, [])
        self.assertEqual(hasil["subjudul"], "SQL Injection pada endpoint walidata-inbox")
        self.assertTrue(hasil["deskripsi_khusus"].startswith("- "))
        self.assertEqual(hasil["rekom_khusus"].count("\n- ") + 1, 2)
        self.assertEqual(hasil["rekomendasi"]["perban4"]["nilai"], "d. validasi input")
        self.assertEqual(hasil["rekomendasi"]["owasptop10"]["nilai"], "A03:2021")
        self.assertEqual(hasil["rekomendasi"]["id_kamus_kerentanan"]["nilai"], 1)
        self.assertTrue(any("Dampak disusun AI" in c for c in catatan))

    def test_poc_step_losing_technical_part_falls_back_to_original(self):
        poc = ["Kirim request ke endpoint (sqlmap).", "Eksploitasi dikonfirmasi: HTTP 200 dengan 11.778 baris."]
        masalah, hasil, catatan = periksa(parse_json(jawaban_ai(langkah_poc=poc)), ASLI)
        self.assertTrue(any("Langkah POC 1" in m for m in masalah))
        self.assertEqual(hasil["langkah_poc"][0], ASLI["langkah_poc"][0])
        self.assertEqual(hasil["langkah_poc"][1], poc[1])  # angka 11,778 -> 11.778 tetap dianggap sama

    def test_wrong_step_count_and_invalid_categories(self):
        masalah, hasil, _ = periksa(parse_json(jawaban_ai(langkah_poc=["satu"], perban4="z", owasptop10="A11",
                                                          id_kamus_kerentanan=42)), ASLI)
        self.assertEqual(hasil["langkah_poc"], ASLI["langkah_poc"])
        self.assertEqual(hasil["rekomendasi"]["perban4"]["nilai"], "")
        self.assertEqual(hasil["rekomendasi"]["owasptop10"]["nilai"], "")
        self.assertIsNone(hasil["rekomendasi"]["id_kamus_kerentanan"]["nilai"])
        self.assertEqual(len(masalah), 4)

    def test_long_title_uses_original(self):
        masalah, hasil, _ = periksa(parse_json(jawaban_ai(subjudul="x" * 150)), ASLI)
        self.assertEqual(hasil["subjudul"], ASLI["subjudul"])
        self.assertTrue(masalah)

    def test_parse_json_tolerates_fences(self):
        self.assertEqual(parse_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertIsNone(parse_json("bukan json"))

    def test_curl_line_must_survive(self):
        asli = "REQUEST:\ncurl -k -H 'Accept: application/json' 'https://t.example/api'"
        self.assertTrue(token_hilang(asli, "Kirim request ke https://t.example/api"))
        self.assertEqual(token_hilang(asli, "Kirim:\ncurl -k -H 'Accept: application/json' 'https://t.example/api'"), [])


class ProsesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.item = item_baru(temuan_transformer())

    def test_retry_then_success_and_cache(self):
        jawaban = iter([jawaban_ai(perban4="z"), jawaban_ai()])
        panggil = []
        def chat(messages):
            panggil.append(messages)
            return next(jawaban)
        proses_item(self.item, chat, "m", self.tmp, 3)
        self.assertEqual(len(panggil), 2)
        self.assertIn("perban4", panggil[1][-1]["content"])  # AI diberi tahu masalahnya
        self.assertEqual(self.item["hasil"]["perban4"], "d. validasi input")
        self.assertEqual(self.item["kategori_sumber"]["perban4"], "rekomendasi_ai")
        self.assertEqual(self.item["status"], "perlu_cek")  # karena dampak disusun AI (catatan)

        item2 = item_baru(temuan_transformer())
        proses_item(item2, lambda m: self.fail("cache tidak dipakai"), "m", self.tmp, 3)
        self.assertEqual(item2["hasil"], self.item["hasil"])

    def test_gives_up_after_max_attempts(self):
        item = item_baru(temuan_transformer())
        proses_item(item, lambda m: "maaf, saya tidak bisa", "m", self.tmp, 2)
        self.assertEqual(item["status"], "perlu_cek")
        self.assertIsNone(item["ai"])
        self.assertEqual(item["hasil"]["subjudul"], ASLI["subjudul"])


class LlmClientTest(unittest.TestCase):
    def test_openai_compatible_server(self):
        diterima = {}

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                diterima["path"] = self.path
                diterima["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                out = json.dumps({"choices": [{"message": {"content": '{"ok": true}'}}]}).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            s = Settings(f"http://127.0.0.1:{srv.server_port}/v1", "model-uji", "", 10, 3, Path("."))
            self.assertEqual(make_chat(s)([{"role": "user", "content": "hai"}]), '{"ok": true}')
            self.assertEqual(diterima["path"], "/v1/chat/completions")
            self.assertEqual(diterima["body"]["model"], "model-uji")
            self.assertEqual(diterima["body"]["temperature"], 0)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_not_configured(self):
        with self.assertRaises(LlmError):
            make_chat(Settings("", "", "", 10, 3, Path(".")))


@unittest.skipIf(TestClient is None, "httpx tidak terpasang")
class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.asli = (api.settings, api.store, api.chat_factory)
        api.settings = Settings("http://ai.lokal/v1", "model-uji", "", 10, 3, self.tmp)
        api.store = api.Store(self.tmp)
        api.chat_factory = lambda s: (lambda messages: jawaban_ai())
        self.c = TestClient(api.app)

    def tearDown(self):
        api.settings, api.store, api.chat_factory = self.asli

    def upload(self, dok, **data):
        return self.c.post("/api/jobs", data=data, files={"file": ("r.siitsa.json", json.dumps(dok), "application/json")})

    def dok(self):
        return {"format": "siitsa.temuan-import/v1", "sumber": {"engagement": "Uji"}, "id_dok_aplikasi": 2,
                "temuan": [temuan_transformer(1), temuan_transformer(2)]}

    def tunggu(self, job_id):
        for _ in range(100):
            j = self.c.get(f"/api/jobs/{job_id}").json()
            if j["status"] != "diproses":
                return j
            time.sleep(0.05)
        self.fail("proses tidak selesai")

    def test_full_flow(self):
        self.assertEqual(self.c.get("/").status_code, 200)
        job = self.upload(self.dok()).json()
        j = self.c.get(f"/api/jobs/{job['id']}").json()
        self.assertEqual(j["temuan"][0]["kemungkinan_duplikat"], [2])  # lokasi + method sama

        self.assertEqual(self.c.post(f"/api/jobs/{job['id']}/proses").json()["jumlah"], 2)
        j = self.tunggu(job["id"])
        self.assertEqual(j["status"], "selesai")
        t = self.c.get(f"/api/jobs/{job['id']}/temuan/1").json()
        self.assertEqual(t["hasil"]["owasptop10"], "A03:2021")

        r = self.c.put(f"/api/jobs/{job['id']}/temuan/1", json={"hasil": {"owasptop10": "A05:2021"}}).json()
        self.assertEqual(r["kategori_sumber"]["owasptop10"], "validator")
        self.assertEqual(r["kategori_sumber"]["perban4"], "rekomendasi_ai")
        self.assertEqual(self.c.put(f"/api/jobs/{job['id']}/temuan/1", json={"hasil": {"perban4": "x"}}).status_code, 422)

        self.assertEqual(self.c.get(f"/api/jobs/{job['id']}/ekspor").status_code, 400)  # belum ada yang disetujui
        self.c.post(f"/api/jobs/{job['id']}/temuan/1/aksi", json={"aksi": "setujui"})
        out = self.c.get(f"/api/jobs/{job['id']}/ekspor").json()
        self.assertEqual(out["ringkasan"]["jumlah_temuan"], 1)
        self.assertEqual(out["ringkasan"]["tidak_diekspor"], 1)
        body = out["temuan"][0]["temuan_itsa"]
        self.assertEqual((body["perban4"], body["owasptop10"], body["id_kamus_kerentanan"]), ("d. validasi input", "A05:2021", 1))
        self.assertEqual((body["cvss"], body["severity"], body["lokasi"]), ("9.3", "Critical", "https://t.example/x (parameter: per_page)"))
        self.assertEqual(list(out["temuan"][0]["langkah_poc"][0]), ["id_temuan", "poc", "gambarpoc"])

    def test_revert_to_original(self):
        job = self.upload(self.dok()).json()
        self.c.post(f"/api/jobs/{job['id']}/proses"); self.tunggu(job["id"])
        t = self.c.post(f"/api/jobs/{job['id']}/temuan/1/aksi", json={"aksi": "kembalikan_asli"}).json()
        self.assertEqual(t["hasil"]["subjudul"], ASLI["subjudul"])
        self.assertEqual(t["hasil"]["perban4"], "d. validasi input")  # kategori tidak ikut dikembalikan

    def test_ai_not_configured_refuses_processing(self):
        api.settings = replace(api.settings, llm_base_url="", llm_model="")
        job = self.upload(self.dok()).json()
        self.assertFalse(self.c.get("/api/status").json()["ai_siap"])
        self.assertEqual(self.c.post(f"/api/jobs/{job['id']}/proses").status_code, 400)
        # Review manual tetap bisa.
        self.assertEqual(self.c.post(f"/api/jobs/{job['id']}/temuan/1/aksi", json={"aksi": "setujui"}).status_code, 200)

    def test_ai_unreachable_sets_error(self):
        def rusak(s):
            def chat(m):
                raise LlmError("AI tidak bisa dihubungi")
            return chat
        api.chat_factory = rusak
        job = self.upload(self.dok()).json()
        self.c.post(f"/api/jobs/{job['id']}/proses")
        j = self.tunggu(job["id"])
        self.assertEqual(j["status"], "gagal")
        self.assertIn("tidak bisa dihubungi", j["error"])
        self.assertTrue(all(t["status"] == "belum_diproses" for t in j["temuan"]))

    def test_stuck_job_recovered_on_server_start_and_resumes(self):
        job = self.upload({**self.dok(), "temuan": [temuan_transformer(1), temuan_transformer(2), temuan_transformer(3)]}).json()
        # Simulasi server mati di tengah proses: #1 sudah selesai (draf), #2 sedang diproses, #3 antre.
        def macet(j):
            j.update(status="diproses", progres={"selesai": 1, "total": 3})
            j["temuan"][0]["status"] = "draf"
            j["temuan"][0]["hasil"]["subjudul"] = "Sudah diproses AI"
            for it in j["temuan"][1:]:
                it["status_sebelum"] = "belum_diproses"
                it["status"] = "diproses"
        api.store.ubah(job["id"], macet)
        self.assertEqual(self.c.put(f"/api/jobs/{job['id']}/temuan/2", json={"hasil": {"subjudul": "x"}}).status_code, 409)

        with TestClient(api.app) as c:  # "with" menjalankan startup server
            j = c.get(f"/api/jobs/{job['id']}").json()
            self.assertEqual(j["status"], "terhenti")
            self.assertIn("terhenti", j["pesan"])
            self.assertEqual([t["status"] for t in j["temuan"]], ["draf", "belum_diproses", "belum_diproses"])
            self.assertEqual(c.get(f"/api/jobs/{job['id']}/temuan/1").json()["hasil"]["subjudul"], "Sudah diproses AI")
            self.assertEqual(c.put(f"/api/jobs/{job['id']}/temuan/2", json={"hasil": {"subjudul": "x"}}).status_code, 200)

            # Lanjutkan: hanya #2 dan #3 yang diproses, hasil #1 tidak ditimpa.
            self.assertEqual(c.post(f"/api/jobs/{job['id']}/proses").json()["jumlah"], 2)
            j = self.tunggu(job["id"])
            self.assertEqual(j["status"], "selesai")
            self.assertIsNone(j["pesan"])
            self.assertEqual(c.get(f"/api/jobs/{job['id']}/temuan/1").json()["hasil"]["subjudul"], "Sudah diproses AI")
            self.assertNotIn("belum_diproses", [t["status"] for t in j["temuan"]])

    def test_recovery_leaves_healthy_jobs_alone(self):
        job = self.upload(self.dok()).json()
        self.assertEqual(api.store.pulihkan_macet(), [])
        self.assertEqual(self.c.get(f"/api/jobs/{job['id']}").json()["status"], "siap")

    def test_raw_its_ai_json_runs_transformer(self):
        raw = {"engagement": {"id": "e", "name": "X"}, "findings": [{
            "id": "f1", "title": "SQL Injection at GET /x", "severity": "high", "status": "accepted",
            "findingClass": "sqli", "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "location": "GET https://t.example/x (param id)", "description": "d", "impact": "i",
            "remediation": "r", "reproSteps": "1) satu\n2) dua"}]}
        job = self.upload(raw, id_dok_aplikasi="7").json()
        self.assertEqual(job["jumlah_temuan"], 1)
        self.assertEqual(job["id_dok_aplikasi"], 7)
        self.assertEqual(self.upload({"foo": 1}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
