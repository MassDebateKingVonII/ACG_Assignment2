import os
from dotenv import load_dotenv
from server.config.db import get_db

load_dotenv()

DB_NAME = os.getenv("DB_NAME")

def init_database():
    print("[*] Connecting to MySQL server...")

    conn = get_db()  # get a connection from the pool
    try:
        with conn.cursor() as cur:
            # Drop database
            print(f"[*] Dropping database '{DB_NAME}' if exists...")
            cur.execute(f"DROP DATABASE IF EXISTS {DB_NAME}")

            # Create database
            print(f"[*] Creating database '{DB_NAME}'...")
            cur.execute(f"CREATE DATABASE {DB_NAME}")

            # Use the new database
            cur.execute(f"USE {DB_NAME}")

            # Create table
            print("[*] Creating table 'encrypted_files'...")
            cur.execute("""
                CREATE TABLE encrypted_files (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL UNIQUE,
                    file JSON NOT NULL,         -- stores ciphertext, nonce, tag
                    enc_dek JSON NOT NULL,      -- stores ciphertext, nonce, tag
                    kek_salt VARCHAR(64) NOT NULL,  -- base64 string
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
    finally:
        conn.close()

    print("Database fully reset and initialized successfully")

if __name__ == "__main__":
    init_database()
