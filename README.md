# Secure File Transfer App: Security & Setup Guide

**Threat Model:** Any user can connect to the server and upload files for sharing.

---

## Security Requirements Fulfillment

| Requirement                          | How It Is Fulfilled                                             | Implementation Details                                                                 |
|--------------------------------------|-----------------------------------------------------------------|--------------------------------------------------------------------------------------|
| **Secure file storage (confidentiality at rest)** | Files encrypted before saving to disk or database               | AES-GCM with per-file DEK; DEK encrypted with KEK derived from MEK                    |
| **Non-repudiation at rest**           | File signatures stored alongside encrypted files               | SHA-256 hash of plaintext signed with server private key; stored in DB               |
| **Key management (MEK / KEK / DEK)** | DEK per file, KEK derived from MEK for envelope encryption    | PBKDF2-HMAC-SHA256 to derive KEK; AES-GCM to encrypt DEKs                             |
| **Forward secrecy in transit**        | Session key derived per connection using ephemeral keys       | ECDHE key exchange to derive AES session key                                         |
| **Server authentication**             | Client verifies server identity during handshake              | Server certificate signed by trusted root CA; verified by client                      |
| **Integrity in transit**              | Messages authenticated with AES-GCM AAD                        | Filename used as AAD; decrypt_message verifies integrity                              |
| **Encrypted file storage format**     | Files stored as binary on disk; DB stores metadata & encrypted DEK | JSON stores enc_dek, KEK salt, signature; ciphertext is binary file                   |
| **MEK rotation**                       | Master key can be rotated and DEKs re-encrypted               | Generates new MEK, derives new KEKs per file, updates DB                              |
| **Client-server communication**       | Only encrypted files and handshake messages sent              | AES-GCM symmetric encryption for file transfer; ECDHE handshake                       |

---

## Prerequisites

1. **Create a virtual environment**

    ```bash
    python -m venv .venv
    ```

2. **Activate the virtual environment (Windows)**

    ```bash
    .venv\Scripts\activate
    ```

3. **Install required dependencies**

    ```bash
    pip install -r requirements.txt
    ```

4. **Create a `.env` file**

    ```bash
    MEK=Xkmh6Fko5PHDdY8E1phQDGQ6VdI4xENhi8q80bpQzTU=
    DB_HOST=<yourdbhostname>
    DB_USER=<yourdbusername>
    DB_PASS=<yourdbpassword>
    DB_NAME=<dbname>
    ```

> *Note:* MEK must be a base64 encoded 32-byte word.

---

## Running the Server & Client

1. **Initialise the database**

    ```bash
    python -m server.config.init_db
    ```

2. **Run the server**

    ```bash
    python -m server.main
    ```

> *Note:* This generates multiple certificates, notably `root_cert.pem`. Copy it to:

    client_path/trusted_root_store


3. **Run the client in another terminal window**

    ```bash
    python -m client.main
    ```

4. **Follow the prompts**  
Choose whether to send or receive files as guided by the client interface.