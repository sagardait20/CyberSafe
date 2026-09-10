import sqlite3


def get_db_connection():
    connection = sqlite3.connect("cybersafe.db")
    connection.row_factory = sqlite3.Row

    return connection


if __name__ == "__main__":
    connection = get_db_connection()

    print("Database connected successfully.")

    connection.close()