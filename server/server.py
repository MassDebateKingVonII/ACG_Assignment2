import socket
import threading
import os
import json
from utils.AES_utils import encrypt_message, decrypt_message
from utils.ECDHE_utils import (
    generate_ecdh_keypair,
    serialize_public_key,
    deserialize_public_key,
    derive_aes_key
)

from server.model.fileModel import store_file, list_files, load_file, rotate_master_key

HOST = '127.0.0.1'
PORT = 5001
SAVE_DIR = os.path.join('server_path', 'save')
os.makedirs(SAVE_DIR, exist_ok=True)

server_running = True
server_socket = None

# ---------------- HANDSHAKE ----------------
def perform_handshake(conn):
    priv, pub = generate_ecdh_keypair()

    length = int.from_bytes(conn.recv(4), 'big')
    client_pub = deserialize_public_key(conn.recv(length))

    pub_bytes = serialize_public_key(pub)
    conn.send(len(pub_bytes).to_bytes(4, 'big'))
    conn.send(pub_bytes)

    aes_key = derive_aes_key(priv, client_pub)
    print("[+] Session AES key established")
    return aes_key

# ---------------- SEND FILE ----------------
def send_file(conn, filename, aes_key):
    plaintext = load_file(filename)

    if plaintext is None:
        return False

    aad = filename.encode()
    enc = encrypt_message(plaintext, aes_key, associated_data=aad)

    payload = json.dumps({
        "filename": filename,
        **enc
    }).encode()

    conn.send(len(payload).to_bytes(8, 'big'))
    conn.send(payload)

    print(f"[+] Sent file: {filename}")
    return True
    
# ---------------- SAVE FILE ----------------
def save_file(payload, aes_key):
    aad = payload["filename"].encode()
    plaintext_bytes = decrypt_message(payload, aes_key, associated_data=aad)

    store_file(payload["filename"], plaintext_bytes)

    print(f"[+] Encrypted file stored: {payload['filename']}")

# ---------------- CLIENT HANDLER ----------------
def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    aes_key = perform_handshake(conn)

    try:
        while True:
            cmd = conn.recv(8)
            if not cmd:
                break

            if cmd == b"QUIT":
                print(f"[-] Client {addr} disconnected")
                break

            if cmd == b"FILE":
                # Receiving a file from client
                length = int.from_bytes(conn.recv(8), 'big')
                data = conn.recv(length)
                payload = json.loads(data.decode())
                
                save_file(payload, aes_key)

            if cmd == b"RECV":
                # Client wants a file list
                files = list_files()
                payload = json.dumps(files).encode()
                conn.send(len(payload).to_bytes(8, 'big'))
                conn.send(payload)

                # Receive requested filename
                fname_len = int.from_bytes(conn.recv(8), 'big')
                filename = conn.recv(fname_len).decode()
                enc_path = os.path.join(SAVE_DIR, filename + ".enc")

                if os.path.exists(enc_path):
                    send_file(conn, filename, aes_key)
                else:
                    # Send back an error message so client doesn't hang
                    error_payload = json.dumps({"error": "File does not exist"}).encode()
                    conn.send(len(error_payload).to_bytes(8, 'big'))
                    conn.send(error_payload)
                    print(f"[!] Client requested nonexistent file: {filename}")

    finally:
        conn.close()

# ---------------- SERVER COMMAND THREAD ----------------
def server_command_listener():
    global server_running, server_socket
    while server_running:
        cmd = input("Server command (/shutdown, /rotate): ").strip()

        if cmd == "/shutdown":
            print("[!] Shutting down server...")
            server_running = False
            server_socket.close()
            break

        elif cmd == "/rotate":
            try:
                print("[*] Rotating Master Key (MEK)...")
                rotate_master_key()
                print("[+] Master Key rotation complete!")
            except Exception as e:
                print(f"[!] Error during MEK rotation: {e}")

# ---------------- MAIN SERVER ----------------
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    server_socket = s
    s.bind((HOST, PORT))
    s.listen()
    print("[+] Server listening...")

    threading.Thread(target=server_command_listener, daemon=True).start()

    while server_running:
        try:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except OSError:
            break

print("[+] Server shut down gracefully.")