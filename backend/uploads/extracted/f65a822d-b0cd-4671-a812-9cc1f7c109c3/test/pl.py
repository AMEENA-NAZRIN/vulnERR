from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)

# ------------------------------
# DATABASE CONNECTION
# ------------------------------

def get_db():
    conn = sqlite3.connect("test.db")
    return conn


# ------------------------------
# USER REGISTRATION (VULNERABLE SQL)
# ------------------------------

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ SQL Injection Vulnerability
    query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
    cursor.execute(query)
    conn.commit()

    return "User registered"


# ------------------------------
# LOGIN (VULNERABLE SQL)
# ------------------------------

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ SQL Injection Vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)

    result = cursor.fetchone()

    if result:
        return "Login Successful"
    else:
        return "Invalid Credentials"


# ------------------------------
# SEARCH USER (VULNERABLE SQL)
# ------------------------------

@app.route("/search", methods=["GET"])
def search_user():
    name = request.args.get("name")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ SQL Injection
    query = f"SELECT * FROM users WHERE username LIKE '%{name}%'"
    cursor.execute(query)

    rows = cursor.fetchall()
    return jsonify(rows)


# ------------------------------
# DELETE USER (VULNERABLE SQL)
# ------------------------------

@app.route("/delete", methods=["POST"])
def delete_user():
    user_id = request.form.get("id")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ SQL Injection
    query = f"DELETE FROM users WHERE id = {user_id}"
    cursor.execute(query)
    conn.commit()

    return "User deleted"


# ------------------------------
# SYSTEM PING (COMMAND INJECTION)
# ------------------------------

@app.route("/ping", methods=["GET"])
def ping():
    ip = request.args.get("ip")

    # ❌ Command Injection
    command = "ping -c 1 " + ip
    os.system(command)

    return "Ping executed"


# ------------------------------
# FILE VIEWER (COMMAND INJECTION)
# ------------------------------

@app.route("/view-file", methods=["GET"])
def view_file():
    filename = request.args.get("file")

    # ❌ Command Injection
    command = "cat " + filename
    output = os.popen(command).read()

    return output


# ------------------------------
# BACKUP DATABASE (COMMAND INJECTION)
# ------------------------------

@app.route("/backup", methods=["POST"])
def backup():
    backup_name = request.form.get("backup_name")

    # ❌ Command Injection
    command = f"cp test.db backups/{backup_name}.db"
    subprocess.call(command, shell=True)

    return "Backup created"


# ------------------------------
# CHANGE PASSWORD (DOUBLE TAINT FLOW)
# ------------------------------

@app.route("/change-password", methods=["POST"])
def change_password():
    user_id = request.form.get("id")
    new_password = request.form.get("new_password")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ SQL Injection
    query = "UPDATE users SET password = '" + new_password + "' WHERE id = " + user_id
    cursor.execute(query)
    conn.commit()

    return "Password updated"


# ------------------------------
# EXPORT USERS (OS + SQL MIX)
# ------------------------------

@app.route("/export", methods=["GET"])
def export_users():
    table = request.args.get("table")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ SQL Injection
    query = f"SELECT * FROM {table}"
    cursor.execute(query)
    data = cursor.fetchall()

    # ❌ Command Injection
    filename = request.args.get("filename")
    command = f"echo '{data}' > {filename}.txt"
    os.system(command)

    return "Export completed"


# ------------------------------
# ADMIN COMMAND EXECUTOR
# ------------------------------

@app.route("/admin/exec", methods=["POST"])
def admin_exec():
    cmd = request.form.get("cmd")

    # ❌ Pure Command Injection
    result = subprocess.check_output(cmd, shell=True)
    return result


# ------------------------------
# START SERVER
# ------------------------------

if __name__ == "__main__":
    app.run(debug=True)