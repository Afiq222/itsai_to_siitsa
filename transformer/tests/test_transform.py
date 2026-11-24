import unittest

from siitsa_transformer import TransformError, split_repro_steps, transform_finding, transform_report

SIITSA_KEYS = [
    "id_dok_aplikasi", "id_kamus_kerentanan", "subjudul", "perban4", "owasptop10", "lokasi",
    "deskripsi_khusus", "dampak_khusus", "rekom_khusus", "cvss", "cvss_string", "severity", "method", "status",
]


def finding(**over):
    f = {
        "ref": "F-01",
        "title": "SQL Injection at GET /x (param id)",
        "severity": "critical",
        "cvssVector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvssScore": 9.3,
        "findingClass": "sqli",
        "status": "Open",
        "verification": "demonstrated",
        "affected": {"url": "https://t.example/x", "host": None, "parameter": "id", "method": "get"},
        "narrative": {
            "description": "desc",
            "businessImpact": "impact\n\nCVSS Attack Vector assumption: Network (internet-facing).",
            "reproSteps": "1) satu\n2) dua",
            "remediation": "fix",
            "assumptions": None,
        },
        "evidence": [],
    }
    f.update(over)
    return f


class SplitStepsTest(unittest.TestCase):
    def test_each_line_is_a_step_and_numbers_removed(self):
        self.assertEqual(split_repro_steps("1) satu\n2) dua\n3. tiga"), ["satu", "dua", "tiga"])

    def test_unnumbered_lines_are_separate_steps(self):
        self.assertEqual(split_repro_steps("buka halaman\n\nklik tombol"), ["buka halaman", "klik tombol"])

    def test_continuation_line_joins_previous_numbered_step(self):
        text = "1. AUTH\n2. REQUEST:\n   curl -k 'https://x'\n3. EXPECTED 200"
        self.assertEqual(split_repro_steps(text), ["AUTH", "REQUEST:\ncurl -k 'https://x'", "EXPECTED 200"])

    def test_out_of_sequence_number_is_continuation(self):
        text = "1. kirim 30 request\n30. bukan langkah\n2. cek"
        self.assertEqual(split_repro_steps(text), ["kirim 30 request\n30. bukan langkah", "cek"])

    def test_empty(self):
        self.assertEqual(split_repro_steps(None), [])


class FindingTest(unittest.TestCase):
    def test_body_has_exact_siitsa_keys(self):
        t = transform_finding(finding(), id_dok_aplikasi=7)["temuan_itsa"]
        self.assertEqual(list(t.keys()), SIITSA_KEYS)
        self.assertEqual(t["id_dok_aplikasi"], 7)
        # Tidak ada di data ITS AI: key tetap ada, isinya kosong untuk diisi validator.
        self.assertEqual((t["perban4"], t["owasptop10"], t["id_kamus_kerentanan"]), ("", "", None))
        self.assertEqual(t["cvss"], "9.3")
        self.assertEqual(t["severity"], "Critical")
        self.assertEqual(t["method"], "GET")
        self.assertEqual(t["lokasi"], "https://t.example/x (parameter: id)")
        self.assertEqual(t["dampak_khusus"], "impact")

    def test_poc_steps(self):
        poc = transform_finding(finding())["langkah_poc"]
        self.assertEqual([{k: x[k] for k in ("id_temuan", "poc")} for x in poc],
                         [{"id_temuan": None, "poc": "satu"}, {"id_temuan": None, "poc": "dua"}])
        self.assertEqual([x["gambar_poc"] for x in poc], [None, None])

    def test_severity_from_its_ai_with_warning_on_cvss_mismatch(self):
        r = transform_finding(finding(severity="medium", cvssScore=7.1))
        self.assertEqual(r["temuan_itsa"]["severity"], "Medium")
        self.assertEqual(r["temuan_itsa"]["cvss"], "7.1")
        self.assertTrue(any("tetap dipakai severity ITS AI" in w for w in r["peringatan"]))

    def test_candidate_keeps_ai_severity(self):
        r = transform_finding(finding(severity="info", cvssScore=6.9, findingClass="missing-rate-limit-untested"))
        self.assertEqual(r["temuan_itsa"]["severity"], "Info")
        self.assertTrue(any("Temuan kandidat" in w for w in r["peringatan"]))

    def test_categories_always_empty_without_warning(self):
        for cls in ("sqli", "idor", "broken-access-control", "kelas-baru"):
            r = transform_finding(finding(findingClass=cls))
            t = r["temuan_itsa"]
            self.assertEqual((t["perban4"], t["owasptop10"], t["id_kamus_kerentanan"]), ("", "", None))
            self.assertFalse(any("perban" in w or "owasp" in w or "kamus" in w for w in r["peringatan"]))

    def test_parameter_already_in_url_not_repeated(self):
        aff = {"url": "https://t.example/.htaccess", "parameter": "/.htaccess", "method": "GET"}
        self.assertEqual(transform_finding(finding(affected=aff))["temuan_itsa"]["lokasi"], "https://t.example/.htaccess")


def api_finding(**over):
    """Bentuk finding dari respons API engagement ITS AI."""
    f = {
        "id": "2b38de0e-uuid",
        "title": "Broken access control on POST /api/leave",
        "severity": "medium",
        "status": "rejected",
        "findingClass": "broken-access-control",
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
        "location": "POST https://t.example/api/leave (param EmployeeID, CompanyID)",
        "description": "desc top",
        "impact": "dampak\n\nAsumsi CVSS: Network.",
        "remediation": "rekom",
        "reproSteps": "1) login\n2) kirim",
        "locales": {"descriptionId": "desc id"},
    }
    f.update(over)
    return f


class ApiResponseFormatTest(unittest.TestCase):
    def setUp(self):
        self.r = transform_report({"engagement": {"id": "eng-uuid", "name": "X"}, "findings": [api_finding()]})
        self.t = self.r["temuan"][0]

    def test_cvss_computed_from_vector(self):
        b = self.t["temuan_itsa"]
        self.assertEqual(b["cvss"], "7.1")
        self.assertEqual(b["cvss_string"], api_finding()["cvss"])
        self.assertEqual(b["severity"], "Medium")  # dari ITS AI, bukan rating CVSS (High)

    def test_ids_from_source(self):
        self.assertEqual(self.t["ref"], "2b38de0e-uuid")
        self.assertEqual(self.r["sumber"]["engagement_id"], "eng-uuid")
        # UUID engagement tidak dipakai sebagai id_dok_aplikasi (SIITSA memakai integer)
        self.assertIsNone(self.t["temuan_itsa"]["id_dok_aplikasi"])
        self.assertTrue(self.r["peringatan_umum"])

    def test_id_dok_aplikasi_from_siitsa_is_integer(self):
        r = transform_report({"engagement": {"id": "eng-uuid"}, "findings": [api_finding()]}, id_dok_aplikasi="2")
        self.assertEqual(r["temuan"][0]["temuan_itsa"]["id_dok_aplikasi"], 2)
        self.assertEqual(r["peringatan_umum"], [])
        with self.assertRaises(TransformError):
            transform_report({"findings": []}, id_dok_aplikasi="37ff5025-uuid")

    def test_location_text_and_status(self):
        b = self.t["temuan_itsa"]
        self.assertEqual(b["method"], "POST")
        self.assertEqual(b["lokasi"], "https://t.example/api/leave (parameter: EmployeeID, CompanyID)")
        self.assertEqual(b["deskripsi_khusus"], "desc id")
        self.assertEqual(b["dampak_khusus"], "dampak")
        self.assertEqual(b["status"], "Open")
        self.assertEqual(self.t["status_ai"], "rejected")
        self.assertTrue(any("rejected" in w for w in self.t["peringatan"]))
        self.assertEqual(len(self.t["langkah_poc"]), 2)


PNG = "iVBORw0KGgo="  # cukup sebagai isi base64 untuk uji


class ImageAndFormatTest(unittest.TestCase):
    def evidence(self, caption):
        return {"kind": "screenshot", "caption": caption, "hasImage": True, "image": "data:image/png;base64," + PNG}

    def test_step_screenshot_goes_to_step_others_to_bukti(self):
        f = finding(evidence=[self.evidence("Live pentest step 2/3 - x"), self.evidence("Baseline profile")])
        r = transform_report({"schema": "vacti.findings/v1", "findings": [f]})
        t = r["temuan"][0]
        self.assertIsNone(t["langkah_poc"][0]["gambar_poc"])
        g = t["langkah_poc"][1]["gambar_poc"]
        self.assertEqual((g["nama_file"], g["mime"], g["base64"]), ("F-01-langkah-2.png", "image/png", PNG))
        self.assertEqual([b["nama_file"] for b in t["bukti_gambar"]], ["F-01-bukti-2.png"])
        self.assertEqual((r["ringkasan"]["jumlah_gambar_poc"], r["ringkasan"]["jumlah_bukti_gambar"]), (1, 1))

    def test_step_number_beyond_steps_goes_to_bukti(self):
        f = finding(evidence=[self.evidence("Live pentest step 3/3")])
        t = transform_report({"schema": "vacti.findings/v1", "findings": [f]})["temuan"][0]
        self.assertEqual(len(t["bukti_gambar"]), 1)

    def test_without_images(self):
        f = finding(evidence=[self.evidence("step 1/2")])
        t = transform_report({"findings": [f]}, sertakan_gambar=False)["temuan"][0]
        self.assertIsNone(t["langkah_poc"][0]["gambar_poc"])
        self.assertEqual(t["bukti_gambar"], [])

    def test_format_detected_automatically(self):
        api = {"engagement": {"id": "e"}, "findings": [api_finding()]}
        exp = {"schema": "vacti.findings/v1", "findings": [finding()]}
        self.assertEqual(transform_report(api)["sumber"]["format_input"], "api-response")
        self.assertEqual(transform_report(exp)["sumber"]["format_input"], "findings-export")


class ReportTest(unittest.TestCase):
    def test_rejects_non_its_ai_json(self):
        with self.assertRaises(TransformError):
            transform_report({"foo": 1})

    def test_sorted_by_severity_and_numbered(self):
        data = {"findings": [finding(ref="A", severity="low", cvssScore=3.0), finding(ref="B")]}
        r = transform_report(data)
        self.assertEqual([t["ref"] for t in r["temuan"]], ["B", "A"])
        self.assertEqual([t["no"] for t in r["temuan"]], [1, 2])
        self.assertEqual(r["ringkasan"]["jumlah_langkah_poc"], 4)


if __name__ == "__main__":
    unittest.main()
