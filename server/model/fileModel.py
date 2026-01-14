import os
import base64
import json
from server.config.db import get_db
from server.utils.envelopeEncryption import encrypt_file_at_rest, decrypt_file_at_rest

SAVE_DIR = os.path.join('server_path', 'save')
os.makedirs(SAVE_DIR, exist_ok=True)

import base64

def store_file(filename: str, plaintext_bytes: bytes, signature: bytes):
    # Encrypt file at rest (returns AES dict with ciphertext, nonce, tag)
    enc_data = encrypt_file_at_rest(plaintext_bytes)

    # Save the encrypted file to disk (binary)
    enc_path = os.path.join(SAVE_DIR, filename + ".enc")
    with open(enc_path, "wb") as f:
        f.write(base64.b64decode(enc_data["file"]["ciphertext"]))

    # Base64 encode signature for storage
    signature_b64 = base64.b64encode(signature).decode()

    # Save only metadata and encrypted DEK to database
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO encrypted_files
                (filename, file_nonce, file_tag, enc_dek, kek_salt, file_signature)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                filename,
                enc_data["file"]["nonce"],         # store nonce
                enc_data["file"]["tag"],           # store GCM tag
                json.dumps(enc_data["enc_dek"]),  # AES dict
                enc_data["kek_salt"],             # base64 string
                signature_b64,                     # file signature
            ))
    finally:
        db.close()
     
def list_files():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT filename FROM encrypted_files ORDER BY created_at DESC")
            rows = cur.fetchall()
            return [r[0] for r in rows]
    finally:
        db.close()

def load_file(filename: str) -> tuple[bytes, str] | None:
    db = get_db()
    try:
        with db.cursor(dictionary=True) as cur:
            cur.execute("SELECT * FROM encrypted_files WHERE filename=%s", (filename,))
            row = cur.fetchone()
    finally:
        db.close()

    if not row:
        return None

    # Load ciphertext from disk
    enc_path = os.path.join(SAVE_DIR, filename + ".enc")
    if not os.path.exists(enc_path):
        return None

    with open(enc_path, "rb") as f:
        ciphertext_bytes = f.read()

    # Reconstruct AES dict
    enc_file_dict = {
        "ciphertext": base64.b64encode(ciphertext_bytes).decode(),
        "nonce": row["file_nonce"],
        "tag": row["file_tag"]
    }

    record = {
        "file": enc_file_dict,
        "enc_dek": json.loads(row["enc_dek"]),
        "kek_salt": row["kek_salt"]
    }

    plaintext_bytes = decrypt_file_at_rest(record)
    file_signature = row["file_signature"]
    return plaintext_bytes, file_signature

def get_all_records():
    db = get_db()
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
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE encrypted_files SET enc_dek=%s WHERE id=%s",
                (json.dumps(enc_dek), record_id)
            )
    finally:
        db.close()