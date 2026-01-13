import os, base64

from server.utils.envelopeEncryption import (
    derive_kek, 
    encrypt_dek, 
    decrypt_dek, 
)

from server.model.fileModel import (
    get_all_records,
    update_record_dek
)

MEK_FILE = os.path.join(os.getcwd(), ".env")
MEK_VAR = "MEK"

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