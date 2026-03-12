import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

def get_connection():
        try:
            conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT)
            print("✅ Database Connected Successfully")
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
            password_hash TEXT NOT NULL
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS source_files(
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            filename TEXT,
            code TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS reports(
            id SERIAL PRIMARY KEY,
            file_id INTEGER REFERENCES source_files(id),
            report_pdf BYTEA,
            vulnerabilities_found INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        conn.commit()
        cur.close()
        conn.close()
        print("Table Ready")
    
    except Exception as e:
        print("Table creation error:",e)

def save_code_to_db(user_id, filename, code, result, pdf_bytes, vuln_count):
    try:
        print("Attempting to save to DB")
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO source_files (user_id, filename, code)
            VALUES (%s, %s, %s)
            RETURNING id;
        """, (user_id, filename, code))
        print("insert executed")

        file_id = cur.fetchone()[0]

        cur.execute("""
           INSERT INTO reports (file_id, report_pdf, vulnerabilities_found)
            VALUES (%s, %s, %s);
        """, (file_id, psycopg2.Binary(pdf_bytes),vuln_count))

        print("report inserted")
        conn.commit()
        print("Data stored correctly")

    except Exception as e:
        print("DB ERROR:", e)
        conn.rollback()

    finally:
        cur.close()
        conn.close()

    
  