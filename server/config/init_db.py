import mysql.connector
import os
from dotenv import load_dotenv
from server.config.db import get_db

load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")

def init_database():
    print("[*] Connecting to MySQL server...")

    conn = get_db()

    cur = conn.cursor()

    # Drop database
    print(f"[*] Dropping database '{DB_NAME}' if exists...")
    cur.execute(f"DROP DATABASE IF EXISTS {DB_NAME}")

    # Create database
    print(f"[*] Creating database '{DB_NAME}'...")
    cur.execute(f"CREATE DATABASE {DB_NAME}")

    # Use database
    cur.execute(f"USE {DB_NAME}")

    # Create table
    print("[*] Creating table 'encrypted_files'...")
    cur.execute("""
        CREATE TABLE encrypted_files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            filename VARCHAR(255) NOT NULL UNIQUE,

            enc_dek BLOB NOT NULL,        -- encrypted DEK
            dek_iv VARBINARY(12) NOT NULL,

            kek_salt VARBINARY(16) NOT NULL,

            file_iv VARBINARY(12) NOT NULL,
            file_tag VARBINARY(16) NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    conn.commit()
    cur.close()
    conn.close()

    print("Database fully reset and initialized successfully")

if __name__ == "__main__":
    init_database()
