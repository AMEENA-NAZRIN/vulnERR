import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    try:
        DATABASE_URL = os.getenv("DATABASE_URL")

        # 🚀 If running on Railway
        if DATABASE_URL:
            # Fix for postgres:// issue
            if DATABASE_URL.startswith("postgres://"):
                DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

            conn = psycopg2.connect(DATABASE_URL)
            print("✅ Connected to Railway PostgreSQL")

        # 💻 If running locally (pgAdmin)
        else:
            conn = psycopg2.connect(
                dbname=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT")
            )
            print("✅ Connected to Local PostgreSQL")

        return conn

    except Exception as e:
        print("❌ Database Connection Failed:", e)
        raise


def create_table():
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT
        );
        """)

        cur.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS avatar TEXT;
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS source_files(
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            filename TEXT,
            code TEXT,
            batch_id TEXT,
            zip_filename TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        cur.execute("""
        ALTER TABLE source_files
        ADD COLUMN IF NOT EXISTS batch_id TEXT;
        """)

        cur.execute("""
        ALTER TABLE source_files
        ADD COLUMN IF NOT EXISTS zip_filename TEXT;
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS reports(
            id SERIAL PRIMARY KEY,
            file_id INTEGER REFERENCES source_files(id),
            report_pdf BYTEA,
            vulnerabilities_found INTEGER,
            ai_suggestions TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        cur.execute("""
        ALTER TABLE reports
        ADD COLUMN IF NOT EXISTS ai_suggestions TEXT;
        """)

        conn.commit()
        cur.close()
        conn.close()
        print("✅ Tables Ready")

    except Exception as e:
        print("Table creation error:", e)


def save_code_to_db(user_id, filename, code, result, pdf_bytes, vuln_count,
                     batch_id=None, zip_filename=None, suggestions=""):
    conn    = None
    cur     = None
    file_id = None
    if pdf_bytes is None:
        pdf_bytes = b""
    try:
        print("Attempting to save to DB")
        conn = get_connection()
        cur  = conn.cursor()

        # ── Step 1: Insert source_files FIRST ─────────────
        cur.execute("""
            INSERT INTO source_files (user_id, filename, code, batch_id, zip_filename)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
        """, (user_id, filename, code, batch_id, zip_filename))

        file_id = cur.fetchone()[0]   # ← get id HERE before reports insert

        # ── Step 2: Insert reports SECOND with file_id ────
        cur.execute("""
            INSERT INTO reports (file_id, report_pdf, vulnerabilities_found, ai_suggestions)
            VALUES (%s, %s, %s, %s);
        """, (file_id, psycopg2.Binary(pdf_bytes), vuln_count, suggestions))

        conn.commit()
        print(f"✅ Saved: file_id={file_id}, batch_id={batch_id}")
        return file_id

    except Exception as e:
        print("DB ERROR:", e)
        if conn:
            conn.rollback()
        return None

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()