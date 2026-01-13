import os
import base64
import json
from server.config.db import get_db
from server.utils.envelopeEncryption import encrypt_file_at_rest, decrypt_file_at_rest

SAVE_DIR = os.path.join('server_path', 'save')
os.makedirs(SAVE_DIR, exist_ok=True)

def store_file(filename: str, plaintext_bytes: bytes):
    enc_data = encrypt_file_at_rest(plaintext_bytes)

    # Save encrypted file locally (optional; ciphertext is also in JSON)
    enc_path = os.path.join(SAVE_DIR, filename + ".enc")
    with open(enc_path, "wb") as f:
        f.write(base64.b64decode(enc_data["file"]["ciphertext"]))

    db = get_db()  # get a connection from the pool
    try:
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO encrypted_files
                (filename, file, enc_dek, kek_salt)
                VALUES (%s,%s,%s,%s)
            """, (
                filename,
                json.dumps(enc_data["file"]),      # AES dict as JSON
                json.dumps(enc_data["enc_dek"]),   # AES dict as JSON
                enc_data["kek_salt"]               # base64 string
            ))
        
    finally:
        db.close()
     
def list_files():
    db = get_db()  # get a connection from the pool
    try:
        with db.cursor() as cur:
            cur.execute("SELECT filename FROM encrypted_files ORDER BY created_at DESC")
            rows = cur.fetchall()
            return [r[0] for r in rows]
    finally:
        db.close()

def load_file(filename: str) -> bytes | None:
    db = get_db()  # get a connection from the pool
    try:
        with db.cursor(dictionary=True) as cur:
            cur.execute("SELECT * FROM encrypted_files WHERE filename=%s", (filename,))
            row = cur.fetchone()
    finally:
        db.close()

    if not row:
        return None

    record = {
        "file": json.loads(row["file"]),       # parse JSON dict
        "enc_dek": json.loads(row["enc_dek"]), # parse JSON dict
        "kek_salt": row["kek_salt"]
    }

    return decrypt_file_at_rest(record)

def get_all_records():
    db = get_db()  # get a connection from the pool
    try:
        with db.cursor(dictionary=True) as cur:
            cur.execute("SELECT id, enc_dek, kek_salt FROM encrypted_files")
            return cur.fetchall()
    finally:
        db.close()

def update_record_dek(record_id: int, enc_dek: dict):
    """
    enc_dek: AES dict (ciphertext, nonce, tag)
    """
    db = get_db()  # get a connection from the pool
    try:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE encrypted_files SET enc_dek=%s WHERE id=%s",
                (json.dumps(enc_dek), record_id)
            )
    finally:
        db.close()