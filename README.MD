## Author
Krishna Gajera  
Student ID: 132625971

# Secure UDP Chat Application - README

## Overview
This is a secure UDP-based chat application built in Python as part of the COMPE 560 Homework Assignment. It enables real-time encrypted communication between multiple clients via a central server using hybrid encryption (RSA + AES), message authentication (HMAC), and a curses-based terminal UI. 

---

## Requirements
- Python 3.6 or above
- Dependencies:
  ```bash
  pip install cryptography
  pip install windows-curses  # Only for Windows users
  ```

---

## ▶ How to Run the Application
keep/open folder in one directory 
### 1. Start the Server
Open a terminal window:
```bash
python server_grad.py
```
Expected output:
```
[INFO] Server started on 0.0.0.0:12345
```
This will start the server and listen for incoming client connections.

### 2. Start a Client (in a separate terminal)
```bash
python client_grad.py
```
You will be prompted to enter your username.

Once the client connects:
- An RSA key pair is generated
- The server sends back a unique AES key encrypted with the client's RSA public key
- The secure channel is established

You can now begin chatting with other clients.

You may open multiple terminals and run additional clients to simulate multi-user communication.

### 3. Sending and Receiving Messages
- Messages are encrypted with AES and authenticated with HMAC.
- Status updates are shown in the client UI: `[SENT]`, `[DELIVERED]`, `[FAILED]`.
- Messages from other users are decrypted and displayed in the chat window.

---

## Cryptographic Design Summary

| Mechanism        | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| **RSA (2048-bit)** | Used for securely sharing AES symmetric keys with each client              |
| **AES (128-bit)**  | Used in CBC mode to encrypt chat messages; unique per client               |
| **HMAC (SHA-256)** | Ensures message integrity and authenticity using the AES key              |
| **Base64 Encoding**| Makes binary encrypted messages safe to transmit over text-based UDP       |
| **IV + Padding**   | A random 16-byte IV is generated per message; PKCS7 padding is used        |

---

## Assumptions and Limitations

- The server is trusted to see plaintext messages (not end-to-end encrypted between clients).
- The system assumes a controlled or LAN environment with minimal packet loss.
- Clients are expected to enter their username at launch; it is not securely authenticated.

---

## Files
| File Name           | Purpose                                     |
|---------------------|---------------------------------------------|
| `client_grad.py`     | Client-side logic, UI, encryption      |
| `server_grad.py`     | Server-side message handling and key exchange|
| `crypto_utils_grad.py`| RSA, AES, HMAC utility functions             |
| `chat.log`          | Logs from client-side (sent, delivered, failed)|
| `server_chat.log`   | Server logs (key exchange, messages)        |

---

## Status
- All core and graduate-level requirements are implemented:
  - [x] RSA/AES hybrid encryption
  - [x] AES-CBC encryption + HMAC-SHA256 authentication
  - [x] Error Handling
  - [x] curses-based terminal UI
  - [x] Server and client logging

---



