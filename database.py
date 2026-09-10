import sqlite3
from db import get_db_connection

connection = sqlite3.connect("cybersafe.db")

cursor = connection.cursor()

cursor.execute("""
SELECT * FROM phone_reports
""")

reports = cursor.fetchall()

for report in reports:
    print(report)

connection.close()

def create_url_threats_table():

    connection = get_db_connection()

    connection.execute("""
    CREATE TABLE IF NOT EXISTS url_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    threat_type TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    description TEXT
 )
    """)

    connection.commit()
    connection.close()

def add_url_threats():

    connection = get_db_connection()

    threats = [

        # IP Loggers
        (
            "snifferip.com",
            "IP Logger",
            8,
            "Known IP tracking service"
        ),
        (
            "grabify.link",
            "IP Logger",
            8,
            "Known IP tracking service"
        ),
        (
            "grabify.org",
            "IP Logger",
            8,
            "Known IP tracking service"
        ),
        (
            "iplogger.org",
            "IP Logger",
            8,
            "Known IP tracking service"
        ),
        (
            "iplogger.com",
            "IP Logger",
            8,
            "Known IP tracking service"
        ),

        # URL Shorteners
        (
            "bit.ly",
            "URL Shortener",
            3,
            "URL shortening service can hide the final destination"
        ),
        (
            "tinyurl.com",
            "URL Shortener",
            3,
            "URL shortening service can hide the final destination"
        ),
        (
            "t.co",
            "URL Shortener",
            3,
            "URL shortening service can hide the final destination"
        ),

        # Tracking
        (
            "2no.co",
            "Tracking",
            6,
            "Known link tracking service"
        )
    ]
    

    for threat in threats:

        connection.execute("""
            INSERT OR IGNORE INTO url_threats
            (domain, threat_type, risk_score, description)
            VALUES (?, ?, ?, ?)
        """, threat)

    connection.commit()
    connection.close()

if __name__ == "__main__":

    create_url_threats_table()
    add_url_threats()

    print("URL threat database created successfully.")


