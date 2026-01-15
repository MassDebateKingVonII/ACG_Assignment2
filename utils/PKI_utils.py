import datetime
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

from datetime import datetime, timedelta, timezone

CERT_DIR = os.path.join('server', 'certificates')
os.makedirs(CERT_DIR, exist_ok=True)

ROOT_KEY_PATH = os.path.join(CERT_DIR, "root_key.pem")
ROOT_CERT_PATH = os.path.join(CERT_DIR, "root_cert.pem")
SERVER_KEY_PATH = os.path.join(CERT_DIR, "server_key.pem")
SERVER_CERT_PATH = os.path.join(CERT_DIR, "server_cert.pem")

# ---------------- ROOT CA ----------------
def generate_root_ca():
    """Generate root CA key + self-signed certificate."""
    if os.path.exists(ROOT_KEY_PATH) and os.path.exists(ROOT_CERT_PATH):
        with open(ROOT_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(ROOT_CERT_PATH, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return private_key, cert
    

    now = datetime.now(timezone.utc)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    cert = x509.CertificateBuilder().subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + timedelta(days=3650))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .sign(private_key, hashes.SHA256())

    with open(ROOT_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(ROOT_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return private_key, cert


# ---------------- SERVER CERTIFICATE SIGNING ----------------
def generate_server_certificate(root_key, root_cert, common_name="Server"):
    """Generate a server key and a certificate signed by the root CA."""
    if os.path.exists(SERVER_KEY_PATH) and os.path.exists(SERVER_CERT_PATH):
        with open(SERVER_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(SERVER_CERT_PATH, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return private_key, cert

    now = datetime.now(timezone.utc)
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(root_cert.subject)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + timedelta(days=365))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .sign(root_key, hashes.SHA256())

    with open(SERVER_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(SERVER_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return private_key, cert

def verify_certificate_validity(cert: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    if now < not_before:
        raise Exception("Certificate is not valid yet")

    if now > not_after:
        raise Exception("Certificate has expired")
    
def verify_server_basic_constraints(cert: x509.Certificate) -> None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        raise Exception("BasicConstraints extension missing")

    if ext.value.ca:
        raise Exception("Invalid server certificate: certificate is a CA")

# ---------------- SIGN / VERIFY EPHEMERAL KEYS ----------------
def sign_bytes(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_bytes(public_key, data: bytes, signature: bytes) -> None:
    public_key.verify(
        signature,
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )