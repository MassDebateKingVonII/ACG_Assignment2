from utils.AES_utils import encrypt_message, decrypt_message
from utils.hash_utils import sha256
from utils.PKI_utils import sign_bytes
from server.model.fileModel import store_file, list_files, load_file

def save_file_controller(payload, aes_key, server_key):
    """Decrypt and store the file, add signature for non-repudiation."""
    filename = payload["filename"]
    aad = filename.encode()
    
    # Decrypt from the encrypted session
    plaintext_bytes = decrypt_message(payload, aes_key, associated_data=aad)

    file_hash = sha256(plaintext_bytes)
    signature = sign_bytes(server_key, file_hash)
    
    # File will be encrypted at rest via DEK
    store_file(filename, plaintext_bytes, signature)
    return filename

def get_file_list_controller():
    """Return a list of available files."""
    return list_files()

def get_encrypted_file_controller(filename, aes_key):
    """Load file from model and encrypt it (session) for sending."""
    plaintext, file_signature = load_file(filename)
    if plaintext is None:
        return None

    aad = filename.encode()
    enc_payload = encrypt_message(plaintext, aes_key, associated_data=aad)

    return {
        "filename": filename,
        **enc_payload,
        "file_signature": file_signature
    }