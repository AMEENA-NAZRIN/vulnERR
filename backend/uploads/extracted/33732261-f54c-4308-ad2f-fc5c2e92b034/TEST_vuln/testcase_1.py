
import os
import sqlite3

def eval_vulnerability():

    user_input = input("Enter calculation: ")

    result = eval(user_input)  

    print("Result:", result)


def command_injection():

    filename = input("Enter filename to display: ")

    os.system("type " + filename)
def sql_injection():

    conn = sqlite3.connect("test.db")

    cursor = conn.cursor()


    username = input("Enter username: ")

    password = input("Enter password: ")


    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"


    cursor.execute(query)  


    print(cursor.fetchall())

def file_read():

    path = input("Enter file path: ")

    with open(path, "r") as f:  

        print(f.read())


def dynamic_execution():

    code = input("Enter python code: ")

    exec(code)   

import pickle

def unsafe_deserialization():

    data = input("Enter serialized data: ")

    obj = pickle.loads(data.encode())

    print(obj)
def main():

    print("Running unsafe functions")

    eval_vulnerability()

    command_injection()

    sql_injection()

    file_read()

    dynamic_execution()


main()
