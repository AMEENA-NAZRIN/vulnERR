import unittest
import json
import sys
from unittest.mock import patch, MagicMock
from io import BytesIO

# =============================================================================
# TEST CATEGORIES & COUNTERS
# =============================================================================

class TestCategoryCounter:
    def __init__(self):
        self.categories = {
            'API Upload': 0, 'API Auth': 0, 'AI Model': 0,
            'PDF': 0, 'Database': 0, 'Edge Cases': 0
        }
        self.results = {cat: {'passed': 0, 'total': 0} for cat in self.categories}

    def mark_test(self, category, passed):
        self.results[category]['total'] += 1
        if passed:
            self.results[category]['passed'] += 1

    def get_percentage(self, category):
        data = self.results[category]
        return (data['passed'] / data['total'] * 100) if data['total'] > 0 else 0

counter = TestCategoryCounter()

# =============================================================================
# TEST SUITE
# =============================================================================

class VulnerrComprehensiveTests(unittest.TestCase):

    def setUp(self):
        try:
            from app import app
            self.app = app
            self.app.config['TESTING'] = True
            self.client = self.app.test_client()
        except ImportError:
            self.app = None
            self.skipTest("app.py not found")
        self.user_id = "1"

    # ─────────────── API UPLOAD (4 tests — 3 pass, 1 fail) ───────────────

    def test_01_upload_missing_file(self):
        """API: Upload without file → 400 [API Upload] ✅"""
        response = self.client.post("/upload", data={"user_id": self.user_id})
        passed = response.status_code == 400
        counter.mark_test('API Upload', passed)
        self.assertEqual(response.status_code, 400)

    def test_02_upload_missing_user_id(self):
        """API: Upload without user_id → 400 [API Upload] ✅"""
        data = {'file': (BytesIO(b"x=1"), 'test.py')}
        response = self.client.post("/upload", data=data,
                                    content_type='multipart/form-data')
        passed = response.status_code == 400
        counter.mark_test('API Upload', passed)
        self.assertEqual(response.status_code, 400)

    def test_03_upload_safe_file_success(self):
        """API: Safe file → 200 + SAFE JSON [API Upload] ✅"""
        with patch('app.analyze_code', return_value={
            "status": "safe", "severity": "None",
            "message": "No vulnerability", "confidence": 98.5,
            "chunk_probs": [0.05], "max_prob": 0.05,
            "risky_chunks": [], "threshold": 0.20
        }), patch('app.generate_pdf', return_value=b"%PDF-fake"), \
           patch('app.save_code_to_db', return_value=1):
            data = {'file': (BytesIO(b"safe code"), 'safe.py'),
                    'user_id': self.user_id}
            response = self.client.post("/upload", data=data,
                                        content_type='multipart/form-data')
            body  = json.loads(response.data)
            passed = response.status_code == 200 and body.get("status") == "safe"
            counter.mark_test('API Upload', passed)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(body.get("status"), "safe")

    def test_04_upload_rate_limiting(self):
        """
        🚀 DEPLOYMENT TEST: API must enforce rate limiting.
        In production, unrestricted upload endpoints allow DoS attacks.
        Must return 429 Too Many Requests after threshold exceeded.
        ❌ EXPECTED TO FAIL — rate limiting not implemented.
        [API Upload]
        """
        responses = []
        for _ in range(15):
            data = {'file': (BytesIO(b"x = 1"), "test.py"),
                    'user_id': self.user_id}
            with patch('app.analyze_code', return_value={
                "status": "safe", "severity": "None",
                "message": "ok", "confidence": 90.0,
                "chunk_probs": [], "max_prob": 0.1,
                "risky_chunks": [], "threshold": 0.20
            }), patch('app.generate_pdf', return_value=b"%PDF-fake"), \
               patch('app.save_code_to_db', return_value=1):
                r = self.client.post("/upload", data=data,
                                     content_type="multipart/form-data")
                responses.append(r.status_code)

        got_rate_limited = 429 in responses
        counter.mark_test('API Upload', got_rate_limited)
        self.assertIn(
            429, responses,
            "❌ DEPLOYMENT FAILURE: No rate limiting after 15 rapid requests. "
            "Fix: pip install flask-limiter → @limiter.limit('10/minute') on /upload"
        )

    # ─────────────── EDGE CASES (3 tests — 2 pass, 1 fail) ───────────────

    def test_06_upload_empty_file(self):
        """Edge: Empty file → valid response [Edge Cases] ✅"""
        data = {'file': (BytesIO(b""), 'empty.py'),
                'user_id': self.user_id}
        response = self.client.post("/upload", data=data,
                                    content_type='multipart/form-data')
        passed = response.status_code == 200
        counter.mark_test('Edge Cases', passed)
        self.assertEqual(response.status_code, 200)

    def test_07_upload_large_file(self):
        """Edge: Large file → still succeeds [Edge Cases] ✅"""
        large_content = b"x=1\n" * 10000
        data = {'file': (BytesIO(large_content), 'large.py'),
                'user_id': self.user_id}
        with patch('app.analyze_code', return_value={
            "status": "safe", "severity": "None",
            "message": "ok", "confidence": 90.0,
            "chunk_probs": [], "max_prob": 0.1,
            "risky_chunks": [], "threshold": 0.20
        }), patch('app.generate_pdf', return_value=b"%PDF-fake"), \
           patch('app.save_code_to_db', return_value=1):
            response = self.client.post("/upload", data=data,
                                        content_type='multipart/form-data')
            passed = response.status_code == 200
            counter.mark_test('Edge Cases', passed)
            self.assertEqual(response.status_code, 200)

    def test_08_upload_zip_bomb_protection(self):
        """
        🚀 DEPLOYMENT TEST: Server must reject ZIP bombs.
        A ZIP bomb (42KB → 4.5 petabytes) crashes unprotected servers
        by exhausting disk and RAM instantly.
        ❌ EXPECTED TO FAIL — ZIP bomb protection not implemented.
        [Edge Cases]
        """
        import zipfile, io
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            bomb_content = b"\x00" * (5 * 1024 * 1024)  # 5MB nulls → tiny zip
            for i in range(5):
                zf.writestr(f"bomb{i}.py", bomb_content)  # 25MB uncompressed
        zip_buffer.seek(0)

        data = {'file': (BytesIO(zip_buffer.read()), "bomb.zip"),
                'user_id': self.user_id}
        response = self.client.post("/upload", data=data,
                                    content_type="multipart/form-data")
        passed = response.status_code in [400, 413]
        counter.mark_test('Edge Cases', passed)
        self.assertIn(
            response.status_code, [400, 413],
            f"❌ DEPLOYMENT FAILURE: Server accepted ZIP bomb "
            f"(got {response.status_code}). "
            f"Fix: Check zipfile.ZipInfo.file_size before extraction. "
            f"Reject if total uncompressed size > 50MB."
        )

    # ─────────────── AI MODEL (11 tests — 9 pass, 2 fail) ────────────────

    def test_09_analyze_returns_dict(self):
        """AI: analyze_code returns a dictionary [AI Model] ✅"""
        from analyzer import analyze_code
        result = analyze_code("def safe(): return 1")
        passed = isinstance(result, dict)
        counter.mark_test('AI Model', passed)
        self.assertIsInstance(result, dict)

    def test_10_analyze_required_keys(self):
        """AI: result has all required keys [AI Model] ✅"""
        from analyzer import analyze_code
        result   = analyze_code("x = 1")
        required = ["status", "severity", "message",
                    "confidence", "chunk_probs", "max_prob", "threshold"]
        passed   = all(k in result for k in required)
        counter.mark_test('AI Model', passed)
        for key in required:
            self.assertIn(key, result)

    def test_11_analyze_empty_code_returns_safe(self):
        """AI: Empty code → safe [AI Model] ✅"""
        from analyzer import analyze_code
        result = analyze_code("")
        passed = result["status"] == "safe"
        counter.mark_test('AI Model', passed)
        self.assertEqual(result["status"], "safe")

    def test_12_analyze_whitespace_returns_safe(self):
        """AI: Whitespace only → safe [AI Model] ✅"""
        from analyzer import analyze_code
        result = analyze_code("   \n\t\n   ")
        passed = result["status"] == "safe"
        counter.mark_test('AI Model', passed)
        self.assertEqual(result["status"], "safe")

    def test_13_analyze_status_valid_value(self):
        """AI: status is safe or vulnerable [AI Model] ✅"""
        from analyzer import analyze_code
        result = analyze_code("import os\nos.system(input())")
        passed = result["status"] in ["safe", "vulnerable"]
        counter.mark_test('AI Model', passed)
        self.assertIn(result["status"], ["safe", "vulnerable"])

    def test_14_analyze_confidence_range(self):
        """AI: confidence between 0 and 100 [AI Model] ✅"""
        from analyzer import analyze_code
        result = analyze_code("x = 1 + 2")
        passed = 0 <= result["confidence"] <= 100
        counter.mark_test('AI Model', passed)
        self.assertGreaterEqual(result["confidence"], 0)
        self.assertLessEqual(result["confidence"], 100)

    def test_15_analyze_chunk_probs_is_list(self):
        """AI: chunk_probs is a list [AI Model] ✅"""
        from analyzer import analyze_code
        result = analyze_code("x = 1")
        passed = isinstance(result["chunk_probs"], list)
        counter.mark_test('AI Model', passed)
        self.assertIsInstance(result["chunk_probs"], list)

    def test_16_analyze_max_prob_range(self):
        """AI: max_prob between 0.0 and 1.0 [AI Model] ✅"""
        from analyzer import analyze_code
        result = analyze_code("x = 1")
        passed = 0.0 <= result["max_prob"] <= 1.0
        counter.mark_test('AI Model', passed)
        self.assertGreaterEqual(result["max_prob"], 0.0)
        self.assertLessEqual(result["max_prob"], 1.0)

    def test_17_analyze_threshold_is_020(self):
        """AI: threshold matches 0.20 [AI Model] ✅"""
        from analyzer import analyze_code
        result = analyze_code("x = 1")
        passed = result["threshold"] == 0.20
        counter.mark_test('AI Model', passed)
        self.assertEqual(result["threshold"], 0.20)

    def test_18_model_adversarial_obfuscation_resistance(self):
        """
        🚀 RESEARCH-LEVEL: Adversarial robustness against obfuscated payloads.
        Attackers base64-encode SQL injection to evade token-level scanners.
        Model must detect both direct and obfuscated versions within 15% gap.
        ❌ EXPECTED TO FAIL — model not trained on obfuscated samples.
        [AI Model]
        """
        from analyzer import analyze_code

        direct_vuln = """
import sqlite3
from flask import request
def login():
    username = request.args.get('username')
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)
"""
        obfuscated_vuln = """
import sqlite3, base64
from flask import request
def login():
    username = request.args.get('username')
    q = base64.b64decode(b'U0VMRUNUICogRlJPTSB1c2Vycw==').decode()
    query = q + " WHERE username='" + username + "'"
    cursor.execute(query)
"""
        r1         = analyze_code(direct_vuln)
        r2         = analyze_code(obfuscated_vuln)
        difference = abs(r1["max_prob"] - r2["max_prob"])
        both_ok    = (r1["status"] == "vulnerable" and
                      r2["status"] == "vulnerable" and
                      difference < 0.15)

        counter.mark_test('AI Model', both_ok)
        self.assertTrue(
            both_ok,
            f"❌ RESEARCH-LEVEL FAILURE: Not adversarially robust. "
            f"Direct={r1['max_prob']:.3f} | Obfuscated={r2['max_prob']:.3f} | "
            f"Gap={difference:.3f} (max allowed: 0.15). "
            f"Fix: Train on obfuscated variants or use AST-based analysis."
        )

    def test_19_model_cross_language_transfer(self):
        """
        🚀 RESEARCH-LEVEL: Cross-language vulnerability detection.
        Model trained on Python must detect identical SQL injection in JavaScript.
        Enterprise codebases mix Python, JS, Java — scanner must cover all.
        ❌ EXPECTED TO FAIL — model only trained on Python data.
        [AI Model]
        """
        from analyzer import analyze_code

        js_vuln = """
const express = require('express');
const mysql   = require('mysql');
const app     = express();
const db      = mysql.createConnection({ host: 'localhost', database: 'users' });

app.get('/login', (req, res) => {
    const username = req.query.username;
    const password = req.query.password;
    const query = "SELECT * FROM users WHERE username='"
                + username + "' AND password='" + password + "'";
    db.query(query, (err, results) => {
        if (results.length > 0) res.send('Login successful');
        else res.send('Invalid credentials');
    });
});
"""
        result = analyze_code(js_vuln)
        passed = result["status"] == "vulnerable" and result["max_prob"] > 0.5
        counter.mark_test('AI Model', passed)
        self.assertTrue(
            passed,
            f"❌ RESEARCH-LEVEL FAILURE: Cannot detect JS SQL injection. "
            f"status={result['status']}, max_prob={result['max_prob']:.3f}. "
            f"Fix: Fine-tune on CodeSearchNet/CrossVul multilingual datasets "
            f"or switch to UniXcoder/CodeT5+ for cross-language understanding."
        )

    # ─────────────── PDF (5 tests — 5 pass) ──────────────────────────────

    def test_20_pdf_safe_file_generates_bytes(self):
        """PDF: safe file → valid bytes [PDF] ✅"""
        try:
            from pdf_generator import generate_pdf
            result    = {"status": "safe", "severity": "None",
                         "message": "No vulnerability detected"}
            pdf_bytes = generate_pdf("test.py", result, "")
            passed    = isinstance(pdf_bytes, bytes) and len(pdf_bytes) > 100
            counter.mark_test('PDF', passed)
            self.assertIsInstance(pdf_bytes, bytes)
            self.assertGreater(len(pdf_bytes), 100)
        except Exception as e:
            counter.mark_test('PDF', False)
            self.fail(str(e))

    def test_21_pdf_vulnerable_file_generates_bytes(self):
        """PDF: vulnerable file → valid bytes [PDF] ✅"""
        try:
            from pdf_generator import generate_pdf
            result      = {"status": "vulnerable", "severity": "High",
                           "message": "Potential taint vulnerability detected"}
            suggestions = "<h3>SQL Injection</h3><p>Use parameterized queries.</p>"
            pdf_bytes   = generate_pdf("vuln.py", result, suggestions)
            passed      = isinstance(pdf_bytes, bytes) and len(pdf_bytes) > 100
            counter.mark_test('PDF', passed)
            self.assertIsInstance(pdf_bytes, bytes)
            self.assertGreater(len(pdf_bytes), 100)
        except Exception as e:
            counter.mark_test('PDF', False)
            self.fail(str(e))

    def test_22_pdf_starts_with_pdf_header(self):
        """PDF: output starts with %PDF magic bytes [PDF] ✅"""
        try:
            from pdf_generator import generate_pdf
            result    = {"status": "safe", "severity": "None", "message": "Clean"}
            pdf_bytes = generate_pdf("check.py", result, "")
            passed    = pdf_bytes[:4] == b"%PDF"
            counter.mark_test('PDF', passed)
            self.assertEqual(pdf_bytes[:4], b"%PDF")
        except Exception as e:
            counter.mark_test('PDF', False)
            self.fail(str(e))

    def test_23_pdf_with_empty_suggestions(self):
        """PDF: empty suggestions → no crash [PDF] ✅"""
        try:
            from pdf_generator import generate_pdf
            result    = {"status": "safe", "severity": "None", "message": "OK"}
            pdf_bytes = generate_pdf("empty.py", result, "")
            passed    = len(pdf_bytes) > 0
            counter.mark_test('PDF', passed)
            self.assertGreater(len(pdf_bytes), 0)
        except Exception as e:
            counter.mark_test('PDF', False)
            self.fail(str(e))

    def test_24_batch_pdf_generates_bytes(self):
        """PDF: generate_batch_pdf → valid bytes [PDF] ✅"""
        try:
            from pdf_generator import generate_batch_pdf
            batch_data = {
                "batch_id": "test-batch-001",
                "total_files": 2, "vulnerable_count": 1, "safe_count": 1,
                "files": [
                    {"filename": "vuln.py", "status": "vulnerable",
                     "severity": "High",   "message": "Found issue",
                     "suggestions": "<h3>SQL Injection</h3><p>Fix it.</p>"},
                    {"filename": "safe.py", "status": "safe",
                     "severity": "None",   "message": "Clean",
                     "suggestions": ""}
                ]
            }
            pdf_bytes = generate_batch_pdf(batch_data)
            passed    = isinstance(pdf_bytes, bytes) and len(pdf_bytes) > 100
            counter.mark_test('PDF', passed)
            self.assertIsInstance(pdf_bytes, bytes)
            self.assertGreater(len(pdf_bytes), 100)
        except Exception as e:
            counter.mark_test('PDF', False)
            self.fail(str(e))
    def test_25_login_missing_credentials(self):
        """API: /login missing fields → 400/401 [API Auth] ✅"""
        response = self.client.post("/login", json={})
        passed = response.status_code in [400, 401]
        counter.mark_test('API Auth', passed)
        self.assertIn(response.status_code, [400, 401])

    def test_26_signup_missing_fields(self):
        """API: /signup missing fields → 400 [API Auth] ✅"""
        response = self.client.post("/signup", json={"username": "test"})
        passed = response.status_code == 400
        counter.mark_test('API Auth', passed)
        self.assertEqual(response.status_code, 400)

    # ─────────────── DATABASE (3 tests — 3 pass) ─────────────────────────

    def test_27_database_save_returns_id(self):
        """DB: save_code_to_db returns file_id on success [Database] ✅"""
        try:
            from database import save_code_to_db
            with patch('database.get_connection') as mock_conn:
                mock_cur = MagicMock()
                mock_cur.fetchone.return_value = [42]
                mock_conn.return_value.cursor.return_value = mock_cur

                result = save_code_to_db(
                    user_id=1, filename="test.py", code="x=1",
                    result={"status": "safe"}, pdf_bytes=b"%PDF-fake",
                    vuln_count=0, suggestions=""
                )
                passed = result == 42
                counter.mark_test('Database', passed)
                self.assertEqual(result, 42)
        except Exception as e:
            counter.mark_test('Database', False)
            self.fail(str(e))

    def test_28_database_returns_none_on_error(self):
        """DB: save_code_to_db returns None on DB error [Database] ✅"""
        try:
            from database import save_code_to_db
            with patch('database.get_connection') as mock_conn:
                mock_conn.side_effect = Exception("DB connection failed")
                result = save_code_to_db(
                    user_id=1, filename="test.py", code="x=1",
                    result={"status": "safe"}, pdf_bytes=b"",
                    vuln_count=0
                )
                passed = result is None
                counter.mark_test('Database', passed)
                self.assertIsNone(result)
        except Exception as e:
            counter.mark_test('Database', False)
            self.fail(str(e))

    def test_29_database_saves_suggestions(self):
        """DB: ai_suggestions saved correctly to reports table [Database] ✅"""
        try:
            from database import save_code_to_db
            with patch('database.get_connection') as mock_conn:
                mock_cur = MagicMock()
                mock_cur.fetchone.return_value = [7]
                mock_conn.return_value.cursor.return_value = mock_cur

                save_code_to_db(
                    user_id=1, filename="vuln.py", code="x=1",
                    result={"status": "vulnerable"}, pdf_bytes=b"%PDF-fake",
                    vuln_count=1, suggestions="<h3>SQL Injection</h3>"
                )

                # Check ai_suggestions was passed in execute call
                calls = [str(c) for c in mock_cur.execute.call_args_list]
                has_suggestions = any("ai_suggestions" in c for c in calls)
                counter.mark_test('Database', has_suggestions)
                self.assertTrue(
                    has_suggestions,
                    "ai_suggestions was not saved to DB"
                )
        except Exception as e:
            counter.mark_test('Database', False)
            self.fail(str(e))

    # =============================================================================
    # REPORT GENERATOR
    # =============================================================================

    def generate_detailed_report(result):
        total  = result.testsRun
        passed = total - len(result.failures) - len(result.errors)

        print("\n" + "="*90)
        print("🛡️  VULNERR COMPREHENSIVE TEST REPORT")
        print("="*90)
        print(f"📊 OVERALL SUMMARY")
        print(f"   Total: {total}    ✅ Passed: {passed}    🎯 {passed/total*100:.1f}%")
        print()
        print("📈 CATEGORY BREAKDOWN")
        print(" " + "-"*68)
        print(f"{'Category':<20} {'Tests':<6} {'Passed':<7} {'Rate':<9} {'Status'}")
        print(" " + "-"*68)

        category_scores = []
        for category in counter.categories:
            cp    = counter.results[category]['passed']
            ct    = counter.results[category]['total']
            rate  = counter.get_percentage(category)
            status = "✅ PASS" if cp == ct and ct > 0 else "⚠️  PARTIAL" if ct > 0 else "─ SKIP"
            print(f"{category:<20} {ct:<6} {cp:<7} {rate:6.1f}%   {status}")
            category_scores.append((category, rate))

        print(" " + "-"*68)
        valid  = [s[1] for s in category_scores if counter.results[s[0]]['total'] > 0]
        avg    = sum(valid) / len(valid) if valid else 0
        print(f"{'AVERAGE':<20} {'':<6} {'':<7} {avg:6.1f}%")

        print("\n" + "🏆 FAILING TESTS (intentional deployment-level failures):")
        print(" " + "-"*68)
        for f in result.failures:
            name = f[0]._testMethodName
            print(f"   ❌ {name}")
        for e in result.errors:
            name = e[0]._testMethodName
            print(f"   💥 {name} (ERROR)")

        print("\n" + "="*90)
        print(f"🎯 FINAL STATUS: {'✅ ALL PASS' if not result.failures and not result.errors else '⚠️  SOME FAILURES (EXPECTED)'}")
        print("="*90)

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("🚀 Starting VulnERR Comprehensive Tests...")
    print("-" * 90)

    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromTestCase(VulnerrComprehensiveTests)
    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=1)
    result = runner.run(suite)

    generate_detailed_report(result)
    sys.exit(0 if not result.failures and not result.errors else 1)

