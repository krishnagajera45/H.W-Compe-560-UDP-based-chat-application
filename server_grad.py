#!/usr/bin/env python3
"""
server_grad.py

A secure UDP chat server that:
- Performs RSA (2048-bit) ↔ AES-128 key exchanges with clients
- Broadcasts encrypted chat messages (AES-CBC + HMAC-SHA256)
- Sends ACKs back to senders
- Uses a small packet header to distinguish message types and encryption
- Logs all key events

This file is self-contained and has no external dependencies beyond the
other crypto and standard-library modules.
"""
import socket
import logging
import struct
import base64
import json
from crypto_utils_grad import (
    generate_aes_key,
    encrypt_with_rsa,
    decrypt_with_aes,
    encrypt_with_aes,
)

# -----------------------------------------------------------------------------
# Inline message packing / unpacking
# -----------------------------------------------------------------------------

# Message type constants
TYPE_REG = 0    # Registration / public key exchange
TYPE_ACK = 1    # Acknowledgment
TYPE_DATA = 2   # Chat data

# Encryption flag constants
FLAG_PLAINTEXT = 0
FLAG_ENCRYPTED = 1

def pack_message(msg_type: int, enc_flag: int, payload: bytes) -> bytes:
    """
    Pack a message into a simple header + payload format over UDP.

    The header layout is:
      - 1 byte: msg_type (0–255)
      - 1 byte: enc_flag (0 or 1)
      - 2 bytes: payload length (big-endian)

    :param msg_type: Packet type (TYPE_REG, TYPE_ACK, or TYPE_DATA).
    :param enc_flag: Encryption flag (FLAG_PLAINTEXT or FLAG_ENCRYPTED).
    :param payload: Raw payload bytes.
    :return: Complete packet bytes ready to send via UDP.
    :raises ValueError: If any field is out of allowed range.
    """
    if not (0 <= msg_type <= 255):
        raise ValueError("msg_type must be 0–255")
    if enc_flag not in (0, 1):
        raise ValueError("enc_flag must be 0 or 1")
    length = len(payload)
    if length > 0xFFFF:
        raise ValueError("payload too large")
    header = struct.pack("!BBH", msg_type, enc_flag, length)
    return header + payload

def unpack_message(data: bytes):
    
    """
    Unpack a packet created by ``pack_message``.

    :param data: Raw bytes received via UDP.
    :return: Tuple (msg_type, enc_flag, payload_bytes).
    :raises ValueError: If the packet is malformed or truncated.
    """
    if len(data) < 4:
        raise ValueError("packet too short")
    msg_type, enc_flag, length = struct.unpack("!BBH", data[:4])
    payload = data[4:4+length]
    if len(payload) != length:
        raise ValueError(f"expected {length} bytes, got {len(payload)}")
    return msg_type, enc_flag, payload

# -----------------------------------------------------------------------------
# Server setup
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("server_chat.log"),
        logging.StreamHandler()
    ]
)

SERVER_IP = "0.0.0.0"
SERVER_PORT = 12345
BUFFER_SIZE = 4096

# Holds client_addr → AES session key
client_keys = {}

# Holds client_addr → RSA public key (for reference, if needed)
client_rsa_keys = {}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))
logging.info(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

# -----------------------------------------------------------------------------
# Broadcast & handler routines
# -----------------------------------------------------------------------------

def broadcast(sender_addr, plaintext: str):
    """
    Encrypt and broadcast a plaintext JSON message to all clients except the sender.

    :param sender_addr: (host, port) tuple of the original sender.
    :param plaintext: JSON-formatted string to broadcast.
    :return: None
    :rtype: None
    """
    for addr, aes_key in client_keys.items():
        if addr == sender_addr:
            continue
        try:
            enc = encrypt_with_aes(aes_key, plaintext)
            packet = pack_message(TYPE_DATA, FLAG_ENCRYPTED, enc.encode())
            sock.sendto(packet, addr)
            logging.info(f"Broadcast to {addr} (TYPE_DATA, ENC).")
        except Exception as e:
            logging.error(f"Broadcast to {addr} failed: {e}")

def handle_loop():
    """
    Main server loop: receive UDP packets and handle registration, chat, and ACK logic.
    :return: None
    :rtype: None
    """
    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        try:
            msg_type, enc_flag, payload = unpack_message(data)
        except Exception as e:
            logging.error(f"Malformed packet from {addr}: {e}")
            continue

        logging.info(f"Packet from {addr}: type={msg_type} enc={enc_flag} len={len(payload)}")

        # 1) New client Key Exchange
        if addr not in client_keys:
            if msg_type == TYPE_REG and enc_flag == FLAG_PLAINTEXT:
                # decode public key, generate AES, return AES encrypted under RSA
                try:
                    rsa_pub = base64.b64decode(payload)
                    aes_key = generate_aes_key()
                    enc_key = encrypt_with_rsa(rsa_pub, aes_key)
                    response = base64.b64encode(enc_key)
                    packet = pack_message(TYPE_REG, FLAG_PLAINTEXT, response)
                    sock.sendto(packet, addr)

                    client_keys[addr] = aes_key
                    client_rsa_keys[addr] = rsa_pub
                    logging.info(f"Completed RSA→AES key exchange with {addr}")
                except Exception as e:
                    logging.error(f"Handshake error for {addr}: {e}")
            else:
                logging.warning(f"Unexpected pre-key-exchange packet from {addr}")
            continue

        # 2) Existing client - must decrypt if encrypted
        aes_key = client_keys[addr]
        if msg_type == TYPE_DATA and enc_flag == FLAG_ENCRYPTED:
            # chat message
            try:
                plain = decrypt_with_aes(aes_key, payload.decode())
                msg = json.loads(plain)
                logging.info(f"Received chat from {addr} id={msg.get('id')}: {msg.get('text')}")
                broadcast(addr, plain)
                # send back ACK
                ack = json.dumps({"type": "ack", "id": msg.get("id")})
                enc_ack = encrypt_with_aes(aes_key, ack)
                packet = pack_message(TYPE_ACK, FLAG_ENCRYPTED, enc_ack.encode())
                sock.sendto(packet, addr)
                logging.info(f"Sent ACK to {addr} for id={msg.get('id')}")
            except Exception as e:
                logging.error(f"Error handling chat from {addr}: {e}")
        else:
            logging.warning(f"Ignored packet from {addr}: type={msg_type}, enc={enc_flag}")

if __name__ == "__main__":
    handle_loop()
