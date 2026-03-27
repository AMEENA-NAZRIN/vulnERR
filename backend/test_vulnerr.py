# test_vulnerr.py
import unittest
from unittest.mock import patch, MagicMock
import torch
import json

# ══════════════════════════════════════════════════════════
# TEST DATA
# ══════════════════════════════════════════════════════════

VULNERABLE_CODE = """
import sqlite3
from flask import Flask, request
app = Flask(__name__)

def login():
    username = request.args.get('username')
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return 'ok'
"""

SAFE_CODE = """
import sqlite3
from flask import Flask, request
app = Flask(__name__)

def login():
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    return 'ok'
"""

COMMAND_INJECTION_CODE = """
import os
from flask import request

def run_cmd():
    cmd = request.args.get('cmd')
    output = os.popen(cmd).read()
    return output
"""

PICKLE_CODE = """
import pickle
import subprocess

class RCE:
    def __reduce__(self):
        return (subprocess.Popen, (['/bin/sh'],))

data = pickle.loads(user_input)
"""

XSS_CODE = """
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name')
    return render_template_string(f'<h1>Hello {name}</h1>')
"""

EMPTY_CODE = ""
WHITESPACE_CODE = "   \n\t\n   "

# ══════════════════════════════════════════════════════════
# 1. ANALYZER TESTS
# ══════════════════════════════════════════════════════════

class TestAnalyzeCode(unittest.TestCase):

    def setUp(self):
        from analyzer import analyze_code
        self.analyze = analyze_code

    # ── Output structure ──────────────────────────────────
    def test_returns_dict(self):
        result = self.analyze(SAFE_CODE)
        self.assertIsInstance(result, dict)

    def test_required_keys_present(self):
        result = self.analyze(SAFE_CODE)
        for key in ["status", "severity", "message", "confidence", "chunk_probs", "max_prob", "threshold"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_status_is_valid_value(self):
        result = self.analyze(SAFE_CODE)
        self.assertIn(result["status"], ["vulnerable", "safe"])

    def test_severity_is_valid_value(self):
        result = self.analyze(SAFE_CODE)
        self.assertIn(result["severity"], ["High", "None"])

    def test_confidence_is_between_0_and_100(self):
        result = self.analyze(SAFE_CODE)
        self.assertGreaterEqual(result["confidence"], 0)
        self.assertLessEqual(result["confidence"], 100)

    def test_chunk_probs_is_list(self):
        result = self.analyze(SAFE_CODE)
        self.assertIsInstance(result["chunk_probs"], list)

    def test_max_prob_between_0_and_1(self):
        result = self.analyze(SAFE_CODE)
        self.assertGreaterEqual(result["max_prob"], 0.0)
        self.assertLessEqual(result["max_prob"], 1.0)

    # ── Edge cases ────────────────────────────────────────
    def test_empty_code_returns_safe(self):
        result = self.analyze(EMPTY_CODE)
        self.assertEqual(result["status"], "safe")

    def test_whitespace_only_returns_safe(self):
        result = self.analyze(WHITESPACE_CODE)
        self.assertEqual(result["status"], "safe")

    def test_very_long_code_does_not_crash(self):
        long_code = "x = 1\n" * 5000
        try:
            result = self.analyze(long_code)
            self.assertIn(result["status"], ["vulnerable", "safe"])
        except Exception as e:
            self.fail(f"Long code crashed analyzer: {e}")

    def test_chunk_probs_not_empty_for_nonempty_code(self):
        result = self.analyze(SAFE_CODE)
        self.assertGreater(len(result["chunk_probs"]), 0)

    def test_risky_chunks_is_list(self):
        result = self.analyze(VULNERABLE_CODE)
        self.assertIsInstance(result["risky_chunks"], list)

    def test_threshold_matches_config(self):
        result = self.analyze(SAFE_CODE)
        self.assertEqual(result["threshold"], 0.20)

    # ── Vulnerable vs Safe ────────────────────────────────
    def test_safe_code_severity_is_none(self):
        result = self.analyze(SAFE_CODE)
        if result["status"] == "safe":
            self.assertEqual(result["severity"], "None")

    def test_vulnerable_code_severity_is_high(self):
        result = self.analyze(VULNERABLE_CODE)
        if result["status"] == "vulnerable":
            self.assertEqual(result["severity"], "High")

    def test_safe_code_risky_chunks_is_empty(self):
        result = self.analyze(SAFE_CODE)
        if result["status"] == "safe":
            self.assertEqual(result["risky_chunks"], [])


# ══════════════════════════════════════════════════════════
# 2. VULN PATTERNS TESTS
# ══════════════════════════════════════════════════════════

class TestVulnPatterns(unittest.TestCase):

    def setUp(self):
        from vuln_patterns import compute_chunk_hint, CWE_PATTERNS
        self.compute_hint = compute_chunk_hint
        self.patterns     = CWE_PATTERNS

    # ── Score range ───────────────────────────────────────
    def test_score_between_0_and_1(self):
        score, _ = self.compute_hint(VULNERABLE_CODE)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_safe_code_scores_low(self):
        score, _ = self.compute_hint("def add(a, b):\n    return a + b")
        self.assertLess(score, 0.3)

    def test_sql_injection_scores_high(self):
        score, _ = self.compute_hint(VULNERABLE_CODE)
        self.assertGreater(score, 0.3)

    def test_command_injection_scores_high(self):
        score, _ = self.compute_hint(COMMAND_INJECTION_CODE)
        self.assertGreater(score, 0.3)

    def test_pickle_exploit_scores_high(self):
        score, _ = self.compute_hint(PICKLE_CODE)
        self.assertGreater(score, 0.3)

    def test_xss_code_scores_high(self):
        score, _ = self.compute_hint(XSS_CODE)
        self.assertGreater(score, 0.3)

    def test_empty_code_scores_zero(self):
        score, cwes = self.compute_hint("")
        self.assertEqual(score, 0.0)
        self.assertEqual(cwes, [])

    # ── Return types ──────────────────────────────────────
    def test_returns_tuple(self):
        result = self.compute_hint(SAFE_CODE)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_detected_cwes_is_list(self):
        _, cwes = self.compute_hint(VULNERABLE_CODE)
        self.assertIsInstance(cwes, list)

    def test_all_cwe_ids_present(self):
        for cwe in ["CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502"]:
            self.assertIn(cwe, self.patterns)

    def test_each_cwe_has_sources_and_sinks(self):
        for cwe, data in self.patterns.items():
            self.assertIn("sources", data, f"{cwe} missing sources")
            self.assertIn("sinks",   data, f"{cwe} missing sinks")
            self.assertGreater(len(data["sources"]), 0, f"{cwe} sources empty")
            self.assertGreater(len(data["sinks"]),   0, f"{cwe} sinks empty")


# ══════════════════════════════════════════════════════════
# 3. DATABASE TESTS
# ══════════════════════════════════════════════════════════

class TestDatabase(unittest.TestCase):

    def setUp(self):
        from database import save_code_to_db
        self.save = save_code_to_db

    @patch("database.get_connection")
    def test_returns_file_id_on_success(self, mock_conn):
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = [42]
        mock_conn.return_value.cursor.return_value = mock_cur

        result = self.save(
            user_id=1, filename="test.py", code="x=1",
            result={"status": "safe"}, pdf_bytes=b"pdf",
            vuln_count=0, suggestions=""
        )
        self.assertEqual(result, 42)

    @patch("database.get_connection")
    def test_returns_none_on_db_error(self, mock_conn):
        mock_conn.side_effect = Exception("DB connection failed")
        result = self.save(
            user_id=1, filename="test.py", code="x=1",
            result={"status": "safe"}, pdf_bytes=b"pdf",
            vuln_count=0
        )
        self.assertIsNone(result)

    @patch("database.get_connection")
    def test_saves_suggestions_to_db(self, mock_conn):
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = [1]
        mock_conn.return_value.cursor.return_value = mock_cur

        self.save(
            user_id=1, filename="test.py", code="x=1",
            result={"status": "vulnerable"}, pdf_bytes=b"pdf",
            vuln_count=1, suggestions="<h3>SQL Injection</h3>"
        )

        # Check that execute was called with ai_suggestions
        calls = [str(c) for c in mock_cur.execute.call_args_list]
        self.assertTrue(
            any("ai_suggestions" in c for c in calls),
            "ai_suggestions was not saved to DB"
        )

    @patch("database.get_connection")
    def test_batch_id_passed_correctly(self, mock_conn):
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = [5]
        mock_conn.return_value.cursor.return_value = mock_cur

        self.save(
            user_id=1, filename="a.py", code="x=1",
            result={}, pdf_bytes=b"x", vuln_count=0,
            batch_id="batch-123"
        )

        calls = [str(c) for c in mock_cur.execute.call_args_list]
        self.assertTrue(any("batch-123" in c for c in calls))

    @patch("database.get_connection")
    def test_rollback_called_on_error(self, mock_conn):
        mock_cur = MagicMock()
        mock_cur.execute.side_effect = Exception("Insert failed")
        mock_conn.return_value.cursor.return_value = mock_cur

        self.save(
            user_id=1, filename="test.py", code="x=1",
            result={}, pdf_bytes=b"x", vuln_count=0
        )
        mock_conn.return_value.rollback.assert_called_once()


# ══════════════════════════════════════════════════════════
# 4. FLASK API TESTS
# ══════════════════════════════════════════════════════════

class TestFlaskAPI(unittest.TestCase):

    def setUp(self):
        from app import app
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.user_id = "1"

    # ── /upload ───────────────────────────────────────────
    def test_upload_no_file_returns_400(self):
        response = self.client.post("/upload", data={"user_id": self.user_id})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn("error", data)

    def test_upload_no_user_id_returns_400(self):
        data = {"file": (b"x=1", "test.py")}
        response = self.client.post("/upload", data=data,
                                     content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)

    @patch("app.analyze_code")
    @patch("app.save_code_to_db")
    @patch("app.generate_pdf")
    def test_upload_safe_file_returns_safe(self, mock_pdf, mock_save, mock_analyze):
        mock_analyze.return_value = {
            "status": "safe", "severity": "None",
            "message": "No vulnerability", "confidence": 95.0,
            "chunk_probs": [0.05], "max_prob": 0.05,
            "risky_chunks": [], "threshold": 0.20
        }
        mock_pdf.return_value   = b"pdf"
        mock_save.return_value  = 1

        from io import BytesIO
        data = {"file": (BytesIO(SAFE_CODE.encode()), "safe.py"),
                "user_id": self.user_id}
        response = self.client.post("/upload", data=data,
                                     content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.data)
        self.assertEqual(body["status"], "safe")
        self.assertFalse(body["batch"])

    @patch("app.analyze_code")
    @patch("app.save_code_to_db")
    @patch("app.generate_pdf")
    @patch("app.get_taint_fix_suggestions")
    def test_upload_vulnerable_file_returns_vulnerable(
            self, mock_llama, mock_pdf, mock_save, mock_analyze):
        mock_analyze.return_value = {
            "status": "vulnerable", "severity": "High",
            "message": "Vulnerability detected", "confidence": 85.0,
            "chunk_probs": [0.85], "max_prob": 0.85,
            "risky_chunks": [1], "threshold": 0.20
        }
        mock_llama.return_value = "<h3>SQL Injection</h3><p>Fix it</p>"
        mock_pdf.return_value   = b"pdf"
        mock_save.return_value  = 2

        from io import BytesIO
        data = {"file": (BytesIO(VULNERABLE_CODE.encode()), "vuln.py"),
                "user_id": self.user_id}
        response = self.client.post("/upload", data=data,
                                     content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.data)
        self.assertEqual(body["status"], "vulnerable")
        self.assertIn("ai_suggestions", body)

    # ── /login ────────────────────────────────────────────
    def test_login_missing_fields_returns_error(self):
        response = self.client.post("/login",
                                     data=json.dumps({}),
                                     content_type="application/json")
        self.assertIn(response.status_code, [400, 401, 500])

    # ── /signup ───────────────────────────────────────────
    def test_signup_missing_fields_returns_400(self):
        response = self.client.post("/signup",
                                     data=json.dumps({"username": "test"}),
                                     content_type="application/json")
        self.assertEqual(response.status_code, 400)

    # ── /download-report ──────────────────────────────────
    def test_download_report_missing_file_id_returns_400(self):
        response = self.client.post("/download-report",
                                     data={"user_id": self.user_id})
        self.assertEqual(response.status_code, 400)

    def test_download_report_missing_user_id_returns_400(self):
        response = self.client.post("/download-report",
                                     data={"file_id": "1"})
        self.assertEqual(response.status_code, 400)


# ══════════════════════════════════════════════════════════
# 5. LLAMA SUGGESTER TESTS
# ══════════════════════════════════════════════════════════

class TestLlamaSuggester(unittest.TestCase):

    def setUp(self):
        from llama_suggester import get_taint_fix_suggestions
        self.suggest = get_taint_fix_suggestions

    @patch("llama_suggester.client")
    def test_returns_html_string(self, mock_client):
        mock_client.chat.completions.create.return_value.choices = [
            MagicMock(message=MagicMock(content="<h3>SQL Injection</h3><p>Fix it</p>"))
        ]
        result = self.suggest(VULNERABLE_CODE)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    @patch("llama_suggester.client")
    def test_returns_error_html_on_exception(self, mock_client):
        mock_client.chat.completions.create.side_effect = Exception("API Error")
        result = self.suggest(VULNERABLE_CODE)
        self.assertIn("<h3>Error</h3>", result)

    @patch("llama_suggester.client")
    def test_strips_whitespace_from_response(self, mock_client):
        mock_client.chat.completions.create.return_value.choices = [
            MagicMock(message=MagicMock(content="  <h3>Test</h3>  "))
        ]
        result = self.suggest(SAFE_CODE)
        self.assertEqual(result, result.strip())


# ══════════════════════════════════════════════════════════
# 6. ZIP HANDLER TESTS
# ══════════════════════════════════════════════════════════

class TestZipHandler(unittest.TestCase):

    def setUp(self):
        from zip_handler import extract_python_files
        self.extract = extract_python_files

    def test_extracts_py_files_only(self):
        import zipfile, tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path     = os.path.join(tmpdir, "test.zip")
            extract_path = os.path.join(tmpdir, "extracted")

            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("good.py",   "x = 1")
                zf.writestr("bad.py",    "y = 2")
                zf.writestr("readme.md", "# readme")
                zf.writestr("data.json", "{}")

            result = self.extract(zip_path, extract_path)
            filenames = [os.path.basename(f) for f in result]

            self.assertIn("good.py", filenames)
            self.assertIn("bad.py",  filenames)
            self.assertNotIn("readme.md", filenames)
            self.assertNotIn("data.json", filenames)

    def test_returns_empty_list_for_no_py_files(self):
        import zipfile, tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path     = os.path.join(tmpdir, "empty.zip")
            extract_path = os.path.join(tmpdir, "extracted")

            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("readme.txt", "hello")

            result = self.extract(zip_path, extract_path)
            self.assertEqual(result, [])

    def test_creates_extract_directory(self):
        import zipfile, tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path     = os.path.join(tmpdir, "test.zip")
            extract_path = os.path.join(tmpdir, "new_dir", "extracted")

            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("a.py", "x=1")

            self.extract(zip_path, extract_path)
            self.assertTrue(os.path.exists(extract_path))

    def test_returns_absolute_paths(self):
        import zipfile, tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path     = os.path.join(tmpdir, "test.zip")
            extract_path = os.path.join(tmpdir, "extracted")

            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("script.py", "x=1")

            result = self.extract(zip_path, extract_path)
            for path in result:
                self.assertTrue(os.path.isabs(path))


# ══════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestAnalyzeCode))
    suite.addTests(loader.loadTestsFromTestCase(TestVulnPatterns))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestFlaskAPI))
    suite.addTests(loader.loadTestsFromTestCase(TestLlamaSuggester))
    suite.addTests(loader.loadTestsFromTestCase(TestZipHandler))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # ── Summary ───────────────────────────────────────────
    total  = result.testsRun
    failed = len(result.failures) + len(result.errors)
    passed = total - failed

    print("\n" + "="*60)
    print(f"  VULNERR UNIT TEST SUMMARY")
    print("="*60)
    print(f"  Total  : {total}")
    print(f"  Passed : {passed} ✅")
    print(f"  Failed : {failed} ❌")
    print(f"  Score  : {round(passed/total*100, 1)}%")
    print("="*60)