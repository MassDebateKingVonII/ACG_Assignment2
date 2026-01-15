import socket
import threading
import json
from cryptography.hazmat.primitives import serialization

from utils.ECDHE_utils import (
    generate_ecdh_keypair,
    serialize_public_key,
    deserialize_public_key,
    derive_aes_key
)
from utils.PKI_utils import generate_root_ca, generate_server_certificate, sign_bytes
from server.utils.rotateMEK import rotate_master_key
from server.controller.fileController import (
    save_file_controller, 
    get_file_list_controller, 
    get_encrypted_file_controller
)

HOST = '127.0.0.1'
PORT = 5001

# Generate / load CA and server cert
root_key, root_cert = generate_root_ca()
server_key, server_cert = generate_server_certificate(root_key, root_cert)

server_running = True
server_socket = None

# ---------------- HANDSHAKE ----------------
def perform_handshake(conn):
    priv, pub = generate_ecdh_keypair()
    pub_bytes = serialize_public_key(pub)
    signature = sign_bytes(server_key, pub_bytes)

    cert_bytes = server_cert.public_bytes(serialization.Encoding.PEM)
    conn.send(len(cert_bytes).to_bytes(4, "big"))
    conn.send(cert_bytes)
    conn.send(len(pub_bytes).to_bytes(4, "big"))
    conn.send(pub_bytes)
    conn.send(len(signature).to_bytes(4, "big"))
    conn.send(signature)

    length = int.from_bytes(conn.recv(4), "big")
    client_pub = deserialize_public_key(conn.recv(length))
    aes_key = derive_aes_key(priv, client_pub)
    print("[+] AES session key established with server authentication")
    return aes_key

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
                length = int.from_bytes(conn.recv(8), 'big')
                data = conn.recv(length)
                payload = json.loads(data.decode())
                saved_file = save_file_controller(payload, aes_key, server_key)
                print(f"[+] File saved: {saved_file}")

            if cmd == b"RECV":
                files = get_file_list_controller()
                payload = json.dumps(files).encode()
                conn.send(len(payload).to_bytes(8, 'big'))
                conn.send(payload)

                # If no files, skip waiting for filename
                if not files:
                    print("[!] No files available for client")
                    continue  # go back to waiting for next client command

                # There are files, now receive filename
                fname_len = int.from_bytes(conn.recv(8), 'big')
                filename = conn.recv(fname_len).decode()

                enc_file = get_encrypted_file_controller(filename, aes_key)
                if enc_file:
                    payload = json.dumps(enc_file).encode()
                    conn.send(len(payload).to_bytes(8, 'big'))
                    conn.send(payload)
                    print(f"[+] Sent file: {filename}")
                else:
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