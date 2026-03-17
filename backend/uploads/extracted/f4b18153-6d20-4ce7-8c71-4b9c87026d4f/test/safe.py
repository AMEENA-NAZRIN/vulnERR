import sqlite3
import datetime
import ast



def connect_db():

    return sqlite3.connect("bank.db")



def create_table():

    conn = connect_db()

    cursor = conn.cursor()

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS users(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT,

        password TEXT,

        balance INTEGER

    )

    """)

    conn.commit()

    conn.close()
def register():

    conn = connect_db()

    cursor = conn.cursor()


    username = input("Enter username: ")

    password = input("Enter password: ")


    cursor.execute(

        """

        INSERT INTO users(username,password,balance)

        VALUES(?,?,?)

        """,

        (username, password, 1000)

    )


    conn.commit()

    conn.close()

    print("Registered")
def login():

    conn = connect_db()

    cursor = conn.cursor()


    username = input("Username: ")

    password = input("Password: ")


    cursor.execute(

        """

        SELECT * FROM users

        WHERE username=?

        AND password=?

        """,

        (username, password)

    )


    user = cursor.fetchone()

    conn.close()


    if user:

        print("Login success")

        return user

    else:

        print("Login failed")

        return None

def calculator():

    expression = input("Enter math expression: ")


    try:

        result = ast.literal_eval(expression)

        print("Result:", result)

    except:

        print("Invalid expression")

def deposit(user, amount):

    conn = connect_db()

    cursor = conn.cursor()

    new_balance = user[3] + int(amount)

    cursor.execute(

        "UPDATE users SET balance=? WHERE id=?",

        (new_balance, user[0])

    )

    conn.commit()

    conn.close()



def withdraw(user, amount):

    conn = connect_db()

    cursor = conn.cursor()

    new_balance = user[3] - int(amount)

    cursor.execute(

        "UPDATE users SET balance=? WHERE id=?",

        (new_balance, user[0])

    )

    conn.commit()

    conn.close()



def banking_menu(user):

    while True:


        print("\n1 Balance")

        print("2 Deposit")

        print("3 Withdraw")

        print("4 Calculator")

        print("5 Exit")


        choice = input()


        if choice == "4":

            calculator()

        elif choice == "5":

            break



def main():

    create_table()


    while True:


        print("\n1 Register")

        print("2 Login")

        print("3 Exit")


        choice = input()


        if choice == "1":

            register()

        elif choice == "2":

            user = login()

            if user:

                banking_menu(user)
        else:
            break


main()
