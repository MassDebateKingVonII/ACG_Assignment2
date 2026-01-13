import os, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
    aes = AESGCM(kek)
    iv = os.urandom(12)
    ct = aes.encrypt(iv, dek, None)
    return iv, ct

def decrypt_dek(enc_dek: bytes, iv: bytes, kek: bytes):
    aes = AESGCM(kek)
    return aes.decrypt(iv, enc_dek, None)

# -------- FILE --------
def encrypt_file_at_rest(plaintext: bytes):
    dek = generate_dek()

    file_iv = os.urandom(12)
    aes_file = AESGCM(dek)
    ciphertext = aes_file.encrypt(file_iv, plaintext, None)

    salt = os.urandom(16)
    kek = derive_kek(salt)

    dek_iv, enc_dek = encrypt_dek(dek, kek)

    return {
        "ciphertext": ciphertext,
        "file_iv": file_iv,
        "file_tag": ciphertext[-16:],
        "enc_dek": enc_dek,
        "dek_iv": dek_iv,
        "kek_salt": salt
    }

def decrypt_file_at_rest(record):
    kek = derive_kek(record["kek_salt"])
    dek = decrypt_dek(record["enc_dek"], record["dek_iv"], kek)

    aes = AESGCM(dek)
    return aes.decrypt(record["file_iv"], record["ciphertext"], None)