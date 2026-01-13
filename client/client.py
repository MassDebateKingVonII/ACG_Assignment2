import socket
import os
import json
from utils.AES_utils import encrypt_message, decrypt_message
from utils.ECDHE_utils import (
    generate_ecdh_keypair,
    serialize_public_key,
    deserialize_public_key,
    derive_aes_key
)

HOST = '127.0.0.1'
PORT = 5001

UPLOAD_DIR = os.path.join('client_path', 'uploads')
DOWNLOAD_DIR = os.path.join('client_path', 'downloads')
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# ---------------- HANDSHAKE ----------------
def perform_handshake(sock):
    priv, pub = generate_ecdh_keypair()

    pub_bytes = serialize_public_key(pub)
    sock.send(len(pub_bytes).to_bytes(4, 'big'))
    sock.send(pub_bytes)

    length = int.from_bytes(sock.recv(4), 'big')
    server_pub = deserialize_public_key(sock.recv(length))

    aes_key = derive_aes_key(priv, server_pub)
    print("[+] Session AES key established")
    return aes_key

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
def receive_file(conn, aes_key):
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

    # Step 6: Decrypt and save
    aad = payload["filename"].encode()
    plaintext_bytes = decrypt_message(payload, aes_key, associated_data=aad)

    save_path = os.path.join(DOWNLOAD_DIR, payload["filename"])
    with open(save_path, 'wb') as f:
        f.write(plaintext_bytes)

    print(f"[+] File downloaded and saved to downloads/{payload['filename']}")
    
# ---------------- MAIN CLIENT ----------------
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    aes_key = perform_handshake(s)

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
            receive_file(s, aes_key)

        else:
            print("[!] Invalid option")