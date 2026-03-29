from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os

'''
from database import get_connection, create_table, save_code_to_db
from psycopg2.extras import RealDictCursor
import psycopg2
import bcrypt
from analyzer import analyze_code
from llama_suggester import get_taint_fix_suggestions
from pdf_generator import generate_pdf
from flask import send_from_directory
from io import BytesIO
import base64
import uuid
import zipfile
from zip_handler import extract_python_files
from pdf_generator import generate_batch_pdf
'''

print("🚀 VulnERR Flask starting...")
print(f"PORT: {os.getenv('PORT', 5000)}")
print(f"DB URL: {'✅' if os.getenv('DATABASE_URL') else '❌ Missing'}")
print(f"Model URL: {os.getenv('MODEL_URL', 'MISSING')}")

from bs4 import BeautifulSoup

def parse_vulnerabilities(html):

    vulns = []

    parts = html.split("<h3>")

    for part in parts[1:]:  # skip first empty section

        section = part.split("</h3>", 1)

        if len(section) < 2:
            continue

        title = section[0].strip()
        body = section[1].strip()

        vulns.append({
            "title": title,
            "fix": body
        })

    return vulns

app = Flask(__name__)
CORS(app, origins=["*"])

def test():
    return jsonify({"status": "Flask ALIVE", "timestamp": "2026-03-29"})

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "flask": "loaded"})

print("✅ Flask routes registered!")
'''
@app.route('/health')
def health():
    try:
        conn = get_connection()
        conn.close()
        print("🩺 Health OK - DB connected")
        return jsonify({
            "status": "healthy",
            "db": True,
            "model": "CodeBERT loaded",
            "python": os.sys.version
        })
    except:
        print("🩺 Health FAIL - DB issue")
        return jsonify({"status": "unhealthy", "db": False}), 503
'''
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

#create_table()

@app.route("/")
def home():
    return send_from_directory("../frontend", "login.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        user_id = request.form.get("user_id")

        if not user_id:
            return jsonify({"error": "User not logged in"}), 400

        filename = file.filename

        # =================================
        # ZIP FILE ANALYSIS
        # =================================
        if filename.endswith(".zip"):

            batch_id = str(uuid.uuid4())

            zip_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(zip_path)

            extract_dir = os.path.join(UPLOAD_FOLDER, "extracted", batch_id)

            py_files = extract_python_files(zip_path, extract_dir)

            results = []

            for path in py_files:

                with open(path, "rb") as f:
                    code = f.read().decode("utf-8", errors="ignore")

                py_filename = os.path.basename(path)
                analysis = analyze_code(code)
                suggestions = ""
                vulnerabilities = []
                if analysis["status"] == "vulnerable":
                    suggestions = get_taint_fix_suggestions(code)
                    vulnerabilities = parse_vulnerabilities(suggestions)

                pdf_bytes = generate_pdf(py_filename, analysis, suggestions)
                vuln_count = len(vulnerabilities)
                saved_id = save_code_to_db(user_id, py_filename, code, analysis, pdf_bytes, vuln_count,
                            batch_id=batch_id, zip_filename=filename, 
                            suggestions=suggestions)

                results.append({
                    "filename": py_filename,
                    "file_id": saved_id,
                    "status": analysis["status"],
                    "severity": analysis["severity"],
                    "vulnerabilities": vulnerabilities
                })

            return jsonify({
                "batch": True,
                "batch_id": batch_id,
                "zip_filename": filename,
                "files": results
            })

        # =================================
        # NORMAL FILE ANALYSIS
        # =================================
        else:

            code = file.read().decode("utf-8", errors="ignore")

            if not code.strip():
                return jsonify({
                    "batch":          False,
                    "file_id":        None,
                    "status":         "safe",
                    "severity":       "None",
                    "message":        "Empty file — nothing to analyze",
                    "confidence":     0.0,
                    "ai_suggestions": ""
                })

            result = analyze_code(code)

            suggestions = ""
            if result["status"] == "vulnerable":
                suggestions = get_taint_fix_suggestions(code)

            pdf_bytes = generate_pdf(filename, result, suggestions)

            vuln_count = 1 if result["status"] == "vulnerable" else 0

            file_id = save_code_to_db(user_id, filename, code, result, pdf_bytes, vuln_count, suggestions=suggestions)

            return jsonify({
                "batch":          False,
                "file_id":        file_id,
                "status":         result.get("status", "safe"),
                "severity":       result.get("severity", "None"),
                "message":        result.get("message", "Analysis complete"),
                "confidence":     result.get("confidence", 0.0),
                "ai_suggestions": suggestions
            })

    except Exception as e:
        print("UPLOAD ERROR:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files["file"]
    code = file.read().decode("utf-8")
    user_id = request.form.get("user_id")
    if not user_id:
        return jsonify({"error": "User not logged in"}), 400

    result = analyze_code(code)

    suggestions = ""
    if result["status"] == "vulnerable":
        suggestions = get_taint_fix_suggestions(code)

    pdf_bytes = generate_pdf(file.filename, result, suggestions)

    vuln_count = 1 if result["status"] == "vulnerable" else 0
    save_code_to_db(user_id, file.filename, code, result, pdf_bytes, vuln_count)

    return jsonify({
        "status": result["status"],
        "severity": result["severity"],
        "message": result["message"],
        "ai_suggestions": suggestions
    })


@app.route("/download-report", methods=["POST"])
def download_report():
    try:
        user_id = request.form.get("user_id")
        file_id = request.form.get("file_id")

        if not user_id:
            return jsonify({"error": "User ID missing"}), 400
        if not file_id:
            return jsonify({"error": "File ID missing"}), 400

        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT sf.filename, r.report_pdf
            FROM source_files sf
            LEFT JOIN reports r ON sf.id = r.file_id
            WHERE sf.id = %s AND sf.user_id = %s
        """, (file_id, user_id))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row or not row["report_pdf"]:
            return jsonify({"error": "Report not found"}), 404

        print(f"DEBUG download-report: serving file_id={file_id}, filename={row['filename']}, pdf_size={len(bytes(row['report_pdf']))}")

        return send_file(
            BytesIO(bytes(row["report_pdf"])),
            as_attachment=True,
            download_name=f"{row['filename']}_report.pdf",
            mimetype="application/pdf"
        )

    except Exception as e:
        print("ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/download-file-report", methods=["POST"])
def download_file_report():
    try:
        filename = request.form.get("filename")
        user_id = request.form.get("user_id")

        if not filename:
            return jsonify({"error": "Filename missing"}), 400
        if not user_id:
            return jsonify({"error": "User ID missing"}), 400

        file_id = request.form.get("file_id")

        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        if file_id:
            cur.execute("""
                SELECT sf.filename, r.report_pdf
                FROM source_files sf
                LEFT JOIN reports r ON sf.id = r.file_id
                WHERE sf.id = %s AND sf.user_id = %s
            """, (file_id, user_id))
        else:
            cur.execute("""
                SELECT sf.filename, r.report_pdf
                FROM source_files sf
                LEFT JOIN reports r ON sf.id = r.file_id
                WHERE sf.filename = %s AND sf.user_id = %s
                ORDER BY sf.uploaded_at DESC
                LIMIT 1
            """, (filename, user_id))

        row = cur.fetchone()
        cur.close()
        conn.close()

        print(f"DEBUG download-file-report: filename={filename}, file_id={file_id}, user_id={user_id}, found={row is not None}")

        if row and row["report_pdf"]:
            print(f"DEBUG: serving from DB, pdf_size={len(bytes(row['report_pdf']))}")
            return send_file(
                BytesIO(bytes(row["report_pdf"])),
                as_attachment=True,
                download_name=f"{filename}_report.pdf",
                mimetype="application/pdf"
            )

        print(f"DEBUG: NOT found in DB, falling back to regenerate")
        return jsonify({"error": "Report not found in database. Please re-analyze the file."}), 404

    except Exception as e:
        print("FILE REPORT ERROR:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/download-batch-report", methods=["POST"])
def download_batch_report():

    try:
        user_id = request.form.get("user_id")
        file_ids_raw = request.form.get("file_ids", "")

        if not user_id:
            return jsonify({"error": "User ID missing"}), 400

        file_ids = [fid.strip() for fid in file_ids_raw.split(",") if fid.strip()]

        if not file_ids:
            return jsonify({"error": "No file IDs provided"}), 400

        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT sf.id, sf.filename, r.report_pdf, r.vulnerabilities_found, 
                r.created_at, r.ai_suggestions                        
            FROM source_files sf
            LEFT JOIN reports r ON sf.id = r.file_id
            WHERE sf.id = ANY(%s) AND sf.user_id = %s
            ORDER BY sf.uploaded_at ASC
        """, ([int(fid) for fid in file_ids], user_id))

        rows = cur.fetchall()
        cur.close()
        conn.close()

        if not rows:
            return jsonify({"error": "No reports found in database"}), 404

        results = []
        vulnerable_count = 0
        safe_count = 0
        batch_id = str(uuid.uuid4())

        for row in rows:
            vuln_count = row["vulnerabilities_found"] or 0
            status = "vulnerable" if vuln_count > 0 else "safe"
            severity = "High" if vuln_count > 0 else "None"

            if status == "vulnerable":
                vulnerable_count += 1
            else:
                safe_count += 1

            results.append({
                "filename": row["filename"],
                "status":   status,
                "severity": severity,
                "message":  "Potential taint vulnerability detected" if vuln_count > 0 else "No taint vulnerability detected",
                "suggestions": row["ai_suggestions"] or ""
            })

        batch_data = {
            "batch_id": batch_id,
            "total_files": len(rows),
            "vulnerable_count": vulnerable_count,
            "safe_count": safe_count,
            "files": results
        }

        pdf_bytes = generate_batch_pdf(batch_data)

        return send_file(
            BytesIO(pdf_bytes),
            as_attachment=True,
            download_name="VulnERR_Batch_Report.pdf",
            mimetype="application/pdf"
        )

    except Exception as e:
        print("BATCH REPORT ERROR:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json(force=True)

        if not data:
            return jsonify({"error": "No JSON received"}), 400

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not username or not email or not password:
            return jsonify({"error": "Missing fields"}), 400

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)
            """,
            (username, email, hashed_password.decode())
        )

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "User registered successfully"})

    except Exception as e:
        print("SIGNUP ERROR:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data["password"].encode()

    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if user and bcrypt.checkpw(password, user["password_hash"].encode()):
        return jsonify({
            "message": "Login successful",
            "user_id": user["id"],
            "username": user["username"]
        })
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/dashboard/<int:user_id>")
def my_reports(user_id):
    print("Fetching reports for user:", user_id)
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT sf.id, sf.filename, sf.uploaded_at,
               sf.batch_id, sf.zip_filename, r.vulnerabilities_found
        FROM source_files sf
        LEFT JOIN reports r ON sf.id = r.file_id
        WHERE sf.user_id = %s
        ORDER BY sf.uploaded_at DESC
    """, (user_id,))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    batches = {}
    solo = []

    for row in rows:
        row["uploaded_at"] = row["uploaded_at"].isoformat() if row["uploaded_at"] else None
        if row["batch_id"]:
            bid = row["batch_id"]
            if bid not in batches:
                batches[bid] = {"files": [], "zip_filename": row.get("zip_filename", "")}
            batches[bid]["files"].append(dict(row))
        else:
            solo.append(dict(row))

    result = []

    for bid, batch_data in batches.items():
        files = batch_data["files"]
        most_recent = max(f["uploaded_at"] for f in files)
        total_vulns = sum(f["vulnerabilities_found"] or 0 for f in files)
        result.append({
            "type": "batch",
            "batch_id": bid,
            "zip_filename": batch_data.get("zip_filename", ""),
            "uploaded_at": most_recent,
            "file_count": len(files),
            "total_vulnerabilities": total_vulns,
            "files": files
        })

    for f in solo:
        result.append({
            "type": "file",
            "id": f["id"],
            "filename": f["filename"],
            "uploaded_at": f["uploaded_at"],
            "vulnerabilities_found": f["vulnerabilities_found"]
        })

    result.sort(key=lambda x: x["uploaded_at"] or "", reverse=True)

    return jsonify(result)


@app.route("/report/<int:file_id>")
def get_report(file_id):
    try:
        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT sf.id, sf.filename, sf.code, sf.uploaded_at,
                   r.vulnerabilities_found, r.report_pdf, r.created_at
            FROM source_files sf
            LEFT JOIN reports r ON sf.id = r.file_id
            WHERE sf.id = %s
        """, (file_id,))

        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return jsonify({"error": "Report not found"}), 404

        pdf_base64 = None
        if row["report_pdf"]:
            pdf_base64 = base64.b64encode(bytes(row["report_pdf"])).decode("utf-8")

        return jsonify({
            "id": row["id"],
            "filename": row["filename"],
            "code": row["code"],
            "uploaded_at": str(row["uploaded_at"]),
            "vulnerabilities_found": row["vulnerabilities_found"],
            "report_pdf": pdf_base64
        })

    except Exception as e:
        print("REPORT FETCH ERROR:", e)
        return jsonify({"error": str(e)}), 500


# ── GET /user/<id> ─────────────────────────────────────────────────────────────
# Returns user details (excluding password_hash). Avatar is returned as base64.
@app.route("/user/<int:user_id>", methods=["GET"])
def get_user(user_id):
    try:
        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT id, username, email, avatar
            FROM users
            WHERE id = %s
        """, (user_id,))

        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "id":       user["id"],
            "username": user["username"],
            "email":    user["email"],
            "avatar":   user["avatar"]   # base64 string or None
        })

    except Exception as e:
        print("GET USER ERROR:", e)
        return jsonify({"error": str(e)}), 500


# ── PUT /user/<id> ─────────────────────────────────────────────────────────────
# Updates username, email, optionally password and avatar.
@app.route("/user/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    try:
        data = request.get_json(force=True)

        if not data:
            return jsonify({"error": "No data provided"}), 400

        username = data.get("username")
        email    = data.get("email")
        password = data.get("password")   # optional — only update if provided
        avatar   = data.get("avatar")     # optional base64 string

        if not username or not email:
            return jsonify({"error": "Username and email are required"}), 400

        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Check if new username is already taken by someone else
        cur.execute("""
            SELECT id FROM users WHERE username = %s AND id != %s
        """, (username, user_id))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Username already taken"}), 409

        # Check if new email is already taken by someone else
        cur.execute("""
            SELECT id FROM users WHERE email = %s AND id != %s
        """, (email, user_id))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Email already in use"}), 409

        # Build query dynamically based on what was provided
        if password and password.strip() != "":
            # Hash the new password before saving
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            cur.execute("""
                UPDATE users
                SET username = %s, email = %s, password_hash = %s, avatar = %s
                WHERE id = %s
            """, (username, email, hashed, avatar, user_id))
        else:
            # No password change — only update other fields
            cur.execute("""
                UPDATE users
                SET username = %s, email = %s, avatar = %s
                WHERE id = %s
            """, (username, email, avatar, user_id))

        conn.commit()

        # Return the updated user (excluding password_hash)
        cur.execute("""
            SELECT id, username, email, avatar FROM users WHERE id = %s
        """, (user_id,))
        updated = cur.fetchone()

        cur.close()
        conn.close()

        return jsonify({
            "id":       updated["id"],
            "username": updated["username"],
            "email":    updated["email"],
            "avatar":   updated["avatar"]
        })

    except Exception as e:
        print("UPDATE USER ERROR:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/batch-upload", methods=["POST"])
def batch_upload():

    try:

        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        user_id = request.form.get("user_id")

        if not user_id:
            return jsonify({"error": "User not logged in"}), 400

        if not file.filename.endswith(".zip"):
            return jsonify({"error": "Upload a ZIP file"}), 400

        batch_id = str(uuid.uuid4())

        zip_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(zip_path)

        extract_dir = os.path.join(UPLOAD_FOLDER, "extracted", batch_id)

        py_files = extract_python_files(zip_path, extract_dir)

        zip_buffer = BytesIO()

        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as report_zip:

            for path in py_files:

                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()

                analysis = analyze_code(code)

                suggestions = ""
                if analysis["status"] == "vulnerable":
                    suggestions = get_taint_fix_suggestions(code)

                pdf_bytes = generate_pdf(
                    os.path.basename(path),
                    analysis,
                    suggestions
                )

                report_name = os.path.basename(path) + "_report.pdf"

                report_zip.writestr(report_name, pdf_bytes)

        zip_buffer.seek(0)

        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name="VulnERR_Batch_Reports.zip",
            mimetype="application/zip"
        )

    except Exception as e:
        print("BATCH ERROR:", e)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)