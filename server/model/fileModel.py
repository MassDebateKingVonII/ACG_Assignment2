import os, json
from server.config.db import get_db
from server.utils.envelopeEncryption import (
    encrypt_file_at_rest, 
    decrypt_file_at_rest
)

SAVE_DIR = os.path.join('server_path', 'save')
os.makedirs(SAVE_DIR, exist_ok=True)


def store_file(filename: str, plaintext_bytes: bytes):
    enc_data = encrypt_file_at_rest(plaintext_bytes)

    # Save encrypted file
    enc_path = os.path.join(SAVE_DIR, filename + ".enc")
    with open(enc_path, "wb") as f:
        f.write(enc_data["ciphertext"])

    # Store metadata in DB
    db = get_db()
    cur = db.cursor()

    cur.execute("""
        INSERT INTO encrypted_files
        (filename, enc_dek, dek_iv, kek_salt, file_iv, file_tag)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (
        filename,
        enc_data["enc_dek"],
        enc_data["dek_iv"],
        enc_data["kek_salt"],
        enc_data["file_iv"],
        enc_data["file_tag"]
    ))

    db.commit()
    cur.close()
    db.close()


def list_files():
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT filename FROM encrypted_files ORDER BY created_at DESC")
    rows = cur.fetchall()

    cur.close()
    db.close()

    return [r[0] for r in rows]


def load_file(filename: str) -> bytes | None:
    db = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT * FROM encrypted_files WHERE filename=%s", (filename,))
    row = cur.fetchone()

    cur.close()
    db.close()

    if not row:
        return None

    enc_path = os.path.join(SAVE_DIR, filename + ".enc")
    if not os.path.exists(enc_path):
        return None

    with open(enc_path, "rb") as f:
        ciphertext = f.read()

    record = {
        "ciphertext": ciphertext,
        "file_iv": row["file_iv"],
        "enc_dek": row["enc_dek"],
        "dek_iv": row["dek_iv"],
        "kek_salt": row["kek_salt"]
    }

    return decrypt_file_at_rest(record)

def get_all_records():
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id, enc_dek, dek_iv, kek_salt FROM encrypted_files")
    rows = cur.fetchall()
    cur.close()
    db.close()
    return rows

def update_record_dek(record_id, enc_dek, dek_iv):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "UPDATE encrypted_files SET enc_dek=%s, dek_iv=%s WHERE id=%s",
        (enc_dek, dek_iv, record_id)
    )
    db.commit()
    cur.close()
    db.close()