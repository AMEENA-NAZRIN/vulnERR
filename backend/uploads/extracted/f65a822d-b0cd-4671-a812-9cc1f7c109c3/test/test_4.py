from flask import request
import sqlite3

def test():
    x = request.form.get("a")
    conn = sqlite3.connect("x")
    cur = conn.cursor()
    cur.execute(x)