from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("test.db")
    return conn



@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")

    conn = get_db()
    cursor = conn.cursor()

    query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
    cursor.execute(query)
    conn.commit()

    return "User registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)

    result = cursor.fetchone()

    if result:
        return "Login Successful"
    else:
        return "Invalid Credentials"



@app.route("/search", methods=["GET"])
def search_user():
    name = request.args.get("name")

    conn = get_db()
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username LIKE '%{name}%'"
    cursor.execute(query)

    rows = cursor.fetchall()
    return jsonify(rows)



@app.route("/delete", methods=["POST"])
def delete_user():
    user_id = request.form.get("id")

    conn = get_db()
    cursor = conn.cursor()

    query = f"DELETE FROM users WHERE id = {user_id}"
    cursor.execute(query)
    conn.commit()

    return "User deleted"


@app.route("/ping", methods=["GET"])
def ping():
    ip = request.args.get("ip")

    command = "ping -c 1 " + ip
    os.system(command)

    return "Ping executed"



@app.route("/view-file", methods=["GET"])
def view_file():
    filename = request.args.get("file")

    command = "cat " + filename
    output = os.popen(command).read()

    return output


@app.route("/backup", methods=["POST"])
def backup():
    backup_name = request.form.get("backup_name")

    command = f"cp test.db backups/{backup_name}.db"
    subprocess.call(command, shell=True)

    return "Backup created"

@app.route("/change-password", methods=["POST"])
def change_password():
    user_id = request.form.get("id")
    new_password = request.form.get("new_password")

    conn = get_db()
    cursor = conn.cursor()

    query = "UPDATE users SET password = '" + new_password + "' WHERE id = " + user_id
    cursor.execute(query)
    conn.commit()

    return "Password updated"


@app.route("/export", methods=["GET"])
def export_users():
    table = request.args.get("table")

    conn = get_db()
    cursor = conn.cursor()

    query = f"SELECT * FROM {table}"
    cursor.execute(query)
    data = cursor.fetchall()

    filename = request.args.get("filename")
    command = f"echo '{data}' > {filename}.txt"
    os.system(command)

    return "Export completed"


@app.route("/admin/exec", methods=["POST"])
def admin_exec():
    cmd = request.form.get("cmd")

    result = subprocess.check_output(cmd, shell=True)
    return result

if __name__ == "__main__":
    app.run(debug=True)