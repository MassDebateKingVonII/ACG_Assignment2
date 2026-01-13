# utils/ECDHE_utils.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_ecdh_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(data):
    return serialization.load_pem_public_key(data)

def derive_aes_key(private_key, peer_public_key, length=32):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=length,          # 32 bytes = AES-256
        salt=None,
        info=b"file-transfer-session",
    ).derive(shared_secret)

    return aes_key