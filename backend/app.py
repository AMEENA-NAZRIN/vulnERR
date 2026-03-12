from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from database import get_connection, create_table, save_code_to_db
from psycopg2.extras import RealDictCursor
import psycopg2
import bcrypt
from analyzer import analyze_code
from llama_suggester import get_taint_fix_suggestions
import os
from pdf_generator import generate_pdf
from flask import send_from_directory
from io import BytesIO
import base64

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

create_table()

@app.route("/")
def home():
    return send_from_directory("../frontend", "login.html")
@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        user_id = int(request.form.get("user_id"))

        if not user_id:
            return jsonify({"error": "User not logged in"}), 400

        code = file.read().decode("utf-8")
        result = analyze_code(code)

        suggestions = ""
        if result["status"] == "vulnerable":
            suggestions = get_taint_fix_suggestions(code)

        pdf_bytes = generate_pdf(file.filename, result, suggestions)  # now returns bytes directly
        vuln_count = 1 if result["status"] == "vulnerable" else 0

        save_code_to_db(user_id, file.filename, code, result, pdf_bytes, vuln_count)

        return jsonify({
            "message": "File stored successfully",
            "status": result["status"],
            "severity": result["severity"],
            "ai_suggestions": suggestions
        })

    except Exception as e:
        print("UPLOAD ERROR:", e)
        return jsonify({"error": str(e)}), 500
@app.route("/analyze", methods=["POST"])
def analyze():
    #code = request.files["file"].read().decode("utf-8")
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
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        user_id = request.form.get("user_id")

        if not user_id:
            return jsonify({"error": "User ID missing"}), 400

        filename = file.filename
        code = file.read().decode("utf-8")

        # Analyze
        result = analyze_code(code)

        suggestions = ""
        if result.get("status") == "vulnerable":
            suggestions = get_taint_fix_suggestions(code)

        # Generate PDF
        pdf_bytes = generate_pdf(file.filename, result, suggestions)

        return send_file(
            BytesIO(pdf_bytes),
            as_attachment=True,
            download_name=f"{file.filename}_report.pdf",
            mimetype="application/pdf"
        )

    except Exception as e:
        print("ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()

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
        #print("User inserted with ID:", user_id)
        cur.close()
        conn.close()

        return jsonify({"message": "User registered successfully"})

    except Exception as e:
        print("SIGNUP ERROR:", e)
        return jsonify({"error": str(e)}), 500
    
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
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
                r.vulnerabilities_found
            FROM source_files sf
            LEFT JOIN reports r ON sf.id = r.file_id
            WHERE sf.user_id = %s
            ORDER BY sf.uploaded_at DESC
        """, (user_id,))

        data = cur.fetchall()

        #  Convert datetime to ISO string
        for row in data:
            if row["uploaded_at"]:
                row["uploaded_at"] = row["uploaded_at"].isoformat()

        cur.close()
        conn.close()

        return jsonify(data)

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

        # Convert PDF bytes to base64 so frontend can embed it
        
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
    
@app.route("/user/<int:user_id>")
def get_user(user_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT *
        FROM users
        WHERE id = %s
    """, (user_id,))

    user = cur.fetchone()

    cur.close()
    conn.close()

    return jsonify(user)

@app.route("/user/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    data = request.json
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET username=%s, email=%s
        WHERE id=%s
    """, (data["username"], data["email"], user_id,))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Profile updated successfully"})
if __name__ == "__main__":
    app.run(debug=True)