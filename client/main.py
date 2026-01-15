import socket, os, json, base64
from cryptography import x509

from utils.AES_utils import encrypt_message, decrypt_message
from cryptography.hazmat.primitives.asymmetric import padding
from utils.ECDHE_utils import (
    generate_ecdh_keypair,
    serialize_public_key,
    deserialize_public_key,
    derive_aes_key
)

from utils.PKI_utils import verify_bytes
from utils.hash_utils import sha256

HOST = '127.0.0.1'
PORT = 5001

UPLOAD_DIR = os.path.join('client_path', 'uploads')
DOWNLOAD_DIR = os.path.join('client_path', 'downloads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

TRUSTED_ROOT_STORE = os.path.join('client_path', 'trusted_root_store')

# ---------------- HANDSHAKE ----------------
# Load trusted root CA certificate (simulates real-world client trust store)
with open(os.path.join(TRUSTED_ROOT_STORE, "root_cert.pem"), "rb") as f:
    root_cert = x509.load_pem_x509_certificate(f.read())
trusted_root_pubkey = root_cert.public_key()

def perform_handshake(sock):
    # Receive server certificate
    length = int.from_bytes(sock.recv(4), "big")
    cert_bytes = sock.recv(length)
    server_cert = x509.load_pem_x509_certificate(cert_bytes)

    # Step 1: Verify that server_cert is signed by trusted root
    try:
        trusted_root_pubkey.verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_cert.signature_hash_algorithm,
        )
        print("[+] Server certificate verified against trusted root CA")
    except Exception as e:
        raise Exception("Server certificate verification failed!") from e

    server_pub_key = server_cert.public_key()

    # Step 2: Receive ephemeral key + signature
    length = int.from_bytes(sock.recv(4), "big")
    server_ephemeral_bytes = sock.recv(length)
    length = int.from_bytes(sock.recv(4), "big")
    signature = sock.recv(length)

    # Step 3: Verify ephemeral key signature with server public key
    verify_bytes(server_pub_key, server_ephemeral_bytes, signature)

    server_ephemeral_pub = deserialize_public_key(server_ephemeral_bytes)

    # Step 4: Generate client ephemeral key
    priv, pub = generate_ecdh_keypair()
    pub_bytes = serialize_public_key(pub)
    sock.send(len(pub_bytes).to_bytes(4, "big"))
    sock.send(pub_bytes)

    # Step 5: Derive AES session key
    aes_key = derive_aes_key(priv, server_ephemeral_pub)
    print("[+] AES session key established with verified server")
    return aes_key, server_pub_key

# ---------------- SEND FILE ----------------
def send_file(conn, filepath, aes_key):
    filename = os.path.basename(filepath)

    with open(filepath, 'rb') as f:  # binary mode
        plaintext_bytes = f.read()

    aad = filename.encode()
    enc = encrypt_message(plaintext_bytes, aes_key, associated_data=aad)

    payload = json.dumps({
        "filename": filename,
        **enc
    }).encode()

    conn.send(b"FILE")
    conn.send(len(payload).to_bytes(8, 'big'))
    conn.send(payload)

    print(f"[+] Sent encrypted file: {filename}")

# ---------------- RECEIVE FILE ----------------
def receive_file(conn, aes_key, server_pub_key):
    # Step 1: Ask server for file list
    conn.send(b"RECV")

    # Step 2: Receive file list
    length = int.from_bytes(conn.recv(8), 'big')
    data = conn.recv(length)
    files = json.loads(data.decode())

    if not files:
        print("[!] No files available on server")
        return

    print("[+] Files available on server:")
    for f in files:
        print(f" - {f}")

    # Step 3: Let user choose a file
    filename = input("Enter filename to download: ").strip()

    # Step 4: Send the filename anyway
    fname_bytes = filename.encode()
    conn.send(len(fname_bytes).to_bytes(8, 'big'))
    conn.send(fname_bytes)

    # Step 5: Receive the file or error
    length = int.from_bytes(conn.recv(8), 'big')
    payload_bytes = conn.recv(length)
    payload = json.loads(payload_bytes.decode())

    if "error" in payload:
        print(f"[!] Server error: {payload['error']}")
        return

    # Step 6: Decrypt
    aad = payload["filename"].encode()
    plaintext_bytes = decrypt_message(payload, aes_key, associated_data=aad)

    # Step 7: Verify server's signature (non-repudiation at rest)
    file_hash = sha256(plaintext_bytes)
    signature_bytes = base64.b64decode(payload["file_signature"])
    try:
        verify_bytes(server_pub_key, file_hash, signature_bytes)
        print("[+] File signature verified successfully!")
    except Exception:
        print("[!] WARNING: File signature verification failed!")

    # Step 8: Save to downloads
    save_path = os.path.join(DOWNLOAD_DIR, payload["filename"])
    with open(save_path, 'wb') as f:
        f.write(plaintext_bytes)

    print(f"[+] File downloaded and saved to downloads/{payload['filename']}")
    
# ---------------- MAIN CLIENT ----------------
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    aes_key, server_pub_key = perform_handshake(s)

    while True:
        print("\n--- MENU ---")
        print("1. Send file to server")
        print("2. Receive file from server")
        print("3. /quit")
        choice = input("Choose option (1/2/3): ").strip()

        if choice == "3" or choice.lower() == "/quit":
            s.send(b"QUIT")
            print("[+] Client disconnected gracefully")
            break

        elif choice == "1":
            # Send file
            files = os.listdir(UPLOAD_DIR)
            if not files:
                print("[!] No files in uploads/ to send")
                continue

            print("[+] Files in uploads/:")
            for f in files:
                print(f" - {f}")

            fname = input("Enter filename to send: ").strip()
            path = os.path.join(UPLOAD_DIR, fname)
            if os.path.exists(path):
                send_file(s, path, aes_key)
            else:
                print("[!] File not found")

        elif choice == "2":
            # Receive file
            receive_file(s, aes_key, server_pub_key)

        else:
            print("[!] Invalid option")