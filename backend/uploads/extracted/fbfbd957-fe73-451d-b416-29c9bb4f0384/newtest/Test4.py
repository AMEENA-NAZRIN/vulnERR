import sqlite3
import pickle
import os
import subprocess

SECRET_KEY = "hardcoded_secret_123"
DB_PASSWORD = "admin123"

def get_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchall()

def run_command(user_input):
    os.system("ping " + user_input)

def load_user_data(data):
    return pickle.loads(data)

def read_file(filename):
    base_dir = "/var/www/files/"
    filepath = base_dir + filename
    with open(filepath, "r") as f:
        return f.read()

def execute_code(user_code):
    eval(user_code)

class UserSession:
    def __init__(self, user_id):
        self.user_id = user_id
        print(f"Session created for user {user_id} with key {SECRET_KEY}")

    def run_report(self, report_name):
        subprocess.call("generate_report.sh " + report_name, shell=True)

    def export_data(self, query):
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reports WHERE id = " + query)
        return cursor.fetchall()