# AES_utils.py
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

def encrypt_message(plaintext: bytes, key, associated_data: bytes = b""):
    """
    Encrypt plaintext using AES-GCM.
    key: AES key (bytes or base64 string)
    associated_data: authenticated but not encrypted data (AAD)
    Returns a dictionary with base64-encoded ciphertext, nonce, and tag.
    Raises ValueError if encryption fails.
    """
    try:
        if isinstance(key, str):
            key = base64.b64decode(key)
            
        if len(key) != 32:  # 256 bits = 32 bytes
            raise ValueError("Key must be 256 bits (32 bytes)")

        nonce = os.urandom(12)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
        ).encryptor()

        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(encryptor.tag).decode()
        }

    except Exception as e:
        raise ValueError("AES-GCM encryption failed") from e


def decrypt_message(enc_dict, key, associated_data: bytes = b"") -> bytes:
    """
    Decrypt a message encrypted with AES-GCM.
    enc_dict: dictionary with base64-encoded ciphertext, nonce, and tag
    key: AES key used for encryption (can be bytes or base64 string)
    associated_data: authenticated but not encrypted data (AAD)
    Raises ValueError if decryption fails.
    """
    try:
        if isinstance(key, str):
            key = base64.b64decode(key)
            
        if len(key) != 32:  # 256 bits = 32 bytes
            raise ValueError("Key must be 256 bits (32 bytes)")

        ciphertext = base64.b64decode(enc_dict["ciphertext"])
        nonce = base64.b64decode(enc_dict["nonce"])
        tag = base64.b64decode(enc_dict["tag"])

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
        ).decryptor()

        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        return decryptor.update(ciphertext) + decryptor.finalize()

    except (InvalidTag, KeyError, ValueError, TypeError) as e:
        raise ValueError("AES-GCM decryption failed") from e  