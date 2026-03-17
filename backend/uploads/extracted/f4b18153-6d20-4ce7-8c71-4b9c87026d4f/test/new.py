from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess
import pickle
import base64

app = Flask(__name__)

def db():
    return sqlite3.connect("test.db")

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username")
    p = request.form.get("password")
    conn = db()
    cur = conn.cursor()
    q = "SELECT * FROM users WHERE username = '" + u + "' AND password = '" + p + "'"
    cur.execute(q)
    return jsonify(cur.fetchall())

@app.route("/user", methods=["GET"])
def user():
    table = request.args.get("table")
    conn = db()
    cur = conn.cursor()
    q = "SELECT * FROM " + table
    cur.execute(q)
    return jsonify(cur.fetchall())

@app.route("/delete", methods=["POST"])
def delete():
    uid = request.form.get("id")
    conn = db()
    cur = conn.cursor()
    q = "DELETE FROM users WHERE id = " + uid
    cur.execute(q)
    conn.commit()
    return "ok"

@app.route("/ping")
def ping():
    ip = request.args.get("ip")
    cmd = "ping -c 1 " + ip
    os.system(cmd)
    return "done"

@app.route("/exec", methods=["POST"])
def exec_cmd():
    cmd = request.form.get("cmd")
    out = subprocess.check_output(cmd, shell=True)
    return out

@app.route("/load", methods=["POST"])
def load():
    data = request.form.get("data")
    raw = base64.b64decode(data)
    obj = pickle.loads(raw)
    return "loaded"

@app.route("/combo", methods=["POST"])
def combo():
    table = request.form.get("table")
    payload = request.form.get("payload")
    file = request.form.get("file")
    conn = db()
    cur = conn.cursor()
    q = "SELECT * FROM " + table
    cur.execute(q)
    data = cur.fetchall()
    os.system("echo '" + str(data) + "' > " + file)
    obj = pickle.loads(base64.b64decode(payload))
    return "processed"

if __name__ == "__main__":
    app.run(debug=True)