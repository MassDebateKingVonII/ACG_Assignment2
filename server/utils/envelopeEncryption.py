import os
import base64
from utils.AES_utils import encrypt_message, decrypt_message
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv

load_dotenv()

MEK = base64.b64decode(os.getenv("MEK"))

# -------- KEK --------
def derive_kek(salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    return kdf.derive(MEK)

# -------- DEK --------
def generate_dek():
    return os.urandom(32)

def encrypt_dek(dek: bytes, kek: bytes):
    return encrypt_message(dek, kek)

def decrypt_dek(enc_dict: dict, kek: bytes):
    return decrypt_message(enc_dict, kek)

# -------- FILE --------
def encrypt_file_at_rest(plaintext: bytes):
    # Generate DEK for file encryption
    dek = generate_dek()

    # Encrypt file with DEK
    enc_file = encrypt_message(plaintext, dek)

    # Generate KEK and encrypt DEK
    salt = os.urandom(16)
    kek = derive_kek(salt)
    enc_dek = encrypt_dek(dek, kek)

    return {
        "file": enc_file,     # dict: ciphertext, nonce, tag
        "enc_dek": enc_dek,   # dict: ciphertext, nonce, tag
        "kek_salt": base64.b64encode(salt).decode()
    }

def decrypt_file_at_rest(record):
    # Re-derive KEK
    salt = base64.b64decode(record["kek_salt"])
    kek = derive_kek(salt)

    # Decrypt DEK
    dek = decrypt_dek(record["enc_dek"], kek)

    # Decrypt file using DEK
    return decrypt_message(record["file"], dek)