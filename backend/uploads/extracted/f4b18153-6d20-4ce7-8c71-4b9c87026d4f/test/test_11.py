import os
import sqlite3
import pickle
import subprocess


DATABASE = "users.db"


def connect_db():
    return sqlite3.connect(DATABASE)


############################
# SQL INJECTION
############################

def login(username, password):

    conn = connect_db()
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"

    cursor.execute(query)

    user = cursor.fetchone()

    conn.close()

    return user


def get_user(user_id):

    conn = connect_db()
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE id=" + user_id

    cursor.execute(query)

    result = cursor.fetchall()

    conn.close()

    return result


############################
# COMMAND INJECTION
############################

def ping_host(host):

    command = "ping -c 3 " + host

    os.system(command)


def run_backup(folder):

    command = "tar -czf backup.tar.gz " + folder

    subprocess.call(command, shell=True)


############################
# CODE INJECTION
############################

def run_user_code(user_input):

    return eval(user_input)


def execute_script(script):

    exec(script)


############################
# UNSAFE DESERIALIZATION
############################

def load_data(data):

    obj = pickle.loads(data)

    return obj


def read_pickle(filename):

    with open(filename, "rb") as f:

        obj = pickle.load(f)

    return obj


############################
# NORMAL FUNCTIONS
############################

def add(a, b):
    return a + b


def greet(name):
    print("Hello", name)


############################
# MAIN
############################

def main():

    greet("User")

    username = input("Enter username: ")

    password = input("Enter password: ")

    login(username, password)

    host = input("Enter host to ping: ")

    ping_host(host)

    expression = input("Enter expression: ")

    print(run_user_code(expression))

    print(add(5, 10))


if __name__ == "__main__":
    main()