import os, base64
from server.config.db import get_db
from server.utils.envelope_encryption import (
    encrypt_file_at_rest, 
    decrypt_file_at_rest, 
    derive_kek, 
    encrypt_dek, 
    decrypt_dek, 
)

MEK_FILE = os.path.join(os.getcwd(), ".env")
MEK_VAR = "MEK"

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

def rotate_master_key():
    global MEK

    new_mek_bytes = os.urandom(32)
    new_mek_b64 = base64.b64encode(new_mek_bytes).decode()

    set_key(MEK_FILE, MEK_VAR, new_mek_b64)
    MEK = new_mek_bytes
    print("[+] MEK rotated and updated in .env")

    # Re-encrypt all DEKs
    records = get_all_records()
    for record in records:
        old_kek = derive_kek(record["kek_salt"])
        dek = decrypt_dek(record["enc_dek"], record["dek_iv"], old_kek)

        new_kek = derive_kek(record["kek_salt"])
        new_dek_iv, new_enc_dek = encrypt_dek(dek, new_kek)

        update_record_dek(record["id"], new_enc_dek, new_dek_iv)

    print(f"[+] Re-encrypted {len(records)} DEKs with the new MEK")
    
def set_key(env_file: str, key: str, value: str):
    """
    Update a key in a .env file, or add it if it doesn't exist.
    """
    lines = []
    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            lines = f.readlines()

    key_found = False
    with open(env_file, "w") as f:
        for line in lines:
            if line.strip().startswith(key + "="):
                f.write(f"{key}={value}\n")
                key_found = True
            else:
                f.write(line)

        if not key_found:
            f.write(f"{key}={value}\n")