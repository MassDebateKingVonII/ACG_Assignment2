This project has ensured the following:

| Requirement                          | How It Is Fulfilled                                             | Method / Implementation Details                                      |
|--------------------------------------|-----------------------------------------------------------------|----------------------------------------------------------------------|
| **Secure file storage (confidentiality at rest)** | Files encrypted before saving to disk / database               | AES-GCM with per-file DEK; DEK encrypted with KEK derived from MEK |
| **Non-repudiation at rest**           | File signatures stored alongside encrypted files               | SHA-256 hash of plaintext signed with server private key; stored in DB |
| **Key management (MEK / KEK / DEK)** | DEK per file, KEK derived from MEK for envelope encryption    | PBKDF2-HMAC-SHA256 to derive KEK; AES-GCM to encrypt DEKs           |
| **Forward secrecy in transit**        | Session key derived per connection using ephemeral keys       | ECDHE key exchange to derive AES session key                        |
| **Server authentication**             | Client verifies server identity during handshake              | Server certificate signed by trusted root CA; verified by client     |
| **Integrity in transit**              | Messages authenticated with AES-GCM AAD                        | Filename used as AAD; decrypt_message verifies integrity             |
| **Encrypted file storage format**     | Files stored as binary on disk; DB stores metadata & encrypted DEK | JSON stores enc_dek, KEK salt, signature; ciphertext is binary file |
| **MEK rotation**                       | Master key can be rotated and DEKs re-encrypted               | Generates new MEK, derives new KEKs per file, updates DB            |
| **Client-server communication**       | Only encrypted files and handshake messages sent              | AES-GCM symmetric encryption for file transfer; ECDHE handshake     |


# Prerequisities

1. Create a .venv environment to run python

```bash
python -m venv .venv
```

2. Assuming you are on Windows, axtivate the virtual environment

```bash
.venv\Scripts\activate
```

3. Install all the required dependencies libaries

```bash
pip install -r requirements.txt
```

# Running the Server & Client
After installing all the required dependencies

1. Initialise the databse

```bash
python -m server.config.init_db
```

2. Run the server

```bash
python -m server.main
```

> Note this generatess multiple certificates, notable of which is `root_cert.pem`, copy this to the
```bash
client_path/trusted_root_store
```

3. Run the client in another terminal window

```bash
python -m client.main
```

4. Follow the prompts on starting the client to either send or recieve files