#!/usr/bin/env python3
"""
client_grad.py

A secure UDP chat client that:
- Registers with server via RSA public key (plaintext)
- Receives AES-128 session key (RSA-encrypted)
- Sends/receives chat messages (AES-CBC + HMAC-SHA256 + Base64)
- Tracks message types via a 1-byte header, encryption flag, and length
- Retransmits on missing ACKs up to MAX_RETRIES
- Displays in a curses UI
- Logs all events to chat.log
"""

import socket
import threading
import base64
import curses
import json
import time
import logging
import struct

from crypto_utils_grad import (
    generate_rsa_keypair,
    decrypt_with_rsa,
    encrypt_with_aes,
    decrypt_with_aes,
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

    The header is:
      - 1 byte: msg_type (0–255)
      - 1 byte: enc_flag (0 or 1)
      - 2 bytes: payload length (big-endian)

    :param msg_type: Packet type (TYPE_REG, TYPE_ACK, or TYPE_DATA).
    :param enc_flag: Encryption flag (FLAG_PLAINTEXT or FLAG_ENCRYPTED).
    :param payload: Raw payload bytes to send.
    :return: Full packet bytes to send via UDP.
    :raises ValueError: If parameters are out of allowed ranges.
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
    Unpack a packet previously created by ``pack_message``.

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
# Client configuration & logging
# -----------------------------------------------------------------------------

SERVER_IP   = "localhost"
SERVER_PORT = 12345
BUFFER_SIZE = 4096

logging.basicConfig(
    filename='chat.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# -----------------------------------------------------------------------------
# Socket setup and initial RSA registration
# -----------------------------------------------------------------------------

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = (SERVER_IP, SERVER_PORT)

private_key, public_key = generate_rsa_keypair()
reg_payload = base64.b64encode(public_key)
reg_packet  = pack_message(TYPE_REG, FLAG_PLAINTEXT, reg_payload)
sock.sendto(reg_packet, server_addr)
logging.info(f"Sent key-exchange registration (TYPE_REG, plaintext) to server [{len(reg_payload)} bytes]")


aes_key = None  # will be set once server replies

message_id_counter = 0
pending_acks = {}
message_status = {}
MAX_RETRIES = 3
RETRY_INTERVAL = 2

# -----------------------------------------------------------------------------
# Receiver and ACK monitor threads
# -----------------------------------------------------------------------------

def receive_messages(sock, chat_win, lock):
    """
    Background thread: receive and handle incoming UDP packets.

    :param sock: The UDP socket bound to the server address.
    :param chat_win: curses window for chat output.
    :param lock: threading.Lock to synchronize UI updates.
    :return: None
    :rtype: None
    """
    global aes_key, pending_acks, message_status
    while True:
        raw, _ = sock.recvfrom(BUFFER_SIZE)
        try:
            msg_type, enc_flag, payload = unpack_message(raw)
        except Exception as e:
            logging.error(f"Unpack error: {e}")
            continue
        logging.info(f"Received pkt: type={msg_type}, enc={enc_flag}, len={len(payload)}")

        # Before AES key is set, expect a plaintext TYPE_REG response
        if aes_key is None:
            if msg_type == TYPE_REG and enc_flag == FLAG_PLAINTEXT:
                try:
                    enc_bytes = base64.b64decode(payload)
                    aes_key = decrypt_with_rsa(private_key, enc_bytes)
                    with lock:
                        chat_win.addstr("Secure channel established.\n")
                        chat_win.refresh()
                    logging.info("AES session key received.")
                except Exception as e:
                    logging.error(f"AES decrypt error: {e}")
            else:
                logging.warning("Unexpected packet before key exchange completion.")
            continue

        # After handshake: only FLAG_ENCRYPTED is valid
        if enc_flag != FLAG_ENCRYPTED:
            logging.warning("Ignored non-encrypted packet after handshake.")
            continue

        # Decrypt payload
        try:
            plaintext = decrypt_with_aes(aes_key, payload.decode())
        except Exception as e:
            logging.error(f"AES decrypt error: {e}")
            continue

        # Parse JSON payload
        try:
            msg = json.loads(plaintext)
        except Exception:
            with lock:
                chat_win.addstr(f"{plaintext}\n")
                chat_win.refresh()
            continue

        # Handle by message type
        if msg_type == TYPE_ACK:
            # ACK for a sent message
            ack_id = msg.get("id")
            pending_acks.pop(ack_id, None)
            message_status[ack_id] = "[DELIVERED]"
            with lock:
                chat_win.addstr(f"[STATUS] Msg {ack_id} → [DELIVERED]\n")
                chat_win.refresh()
            logging.info(f"Received ACK for Msg {ack_id}")
        elif msg_type == TYPE_DATA:
            # Chat message from peer
            sender = msg.get("username", "Unknown")
            text   = msg.get("text", "")
            with lock:
                chat_win.addstr(f"{sender}: {text}\n")
                chat_win.refresh()
            logging.info(f"Chat from {sender}: {text}")
        else:
            logging.warning(f"Ignored pkt with type={msg_type}")

def ack_monitor(sock, server_addr, chat_win, lock):
    """
    Background thread: retransmit unacknowledged messages when needed.

    :param sock: The UDP socket used to send messages.
    :param server_addr: Tuple (host, port) of the server.
    :param chat_win: curses window for status updates.
    :param lock: threading.Lock to synchronize UI updates.
    :return: None
    :rtype: None
    """
    while True:
        time.sleep(1)
        for mid in list(pending_acks):
            packet, ts, retries = pending_acks[mid]
            if time.time() - ts > RETRY_INTERVAL:
                if retries >= MAX_RETRIES:
                    with lock:
                        chat_win.addstr(f"[FAIL] Msg {mid} dropped.\n")
                        chat_win.refresh()
                    logging.error(f"Msg {mid} dropped after {MAX_RETRIES} retries.")
                    pending_acks.pop(mid, None)
                else:
                    logging.warning(f"Resending Msg {mid} (attempt {retries+1})")
                    with lock:
                        chat_win.addstr(f"[RESEND] Msg {mid}\n")
                        chat_win.refresh()
                    sock.sendto(packet, server_addr)
                    pending_acks[mid] = (packet, time.time(), retries+1)

# -----------------------------------------------------------------------------
# Curses UI main loop
# -----------------------------------------------------------------------------

def curses_client(stdscr, username):
    """
    Main curses UI loop: reads user input and displays chat.

    :param stdscr: The main curses screen object.
    :param username: Username string for this client.
    :return: None
    :rtype: None
    """
    global message_id_counter
    curses.echo()
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()
    chat_win  = curses.newwin(max_y-3, max_x, 0, 0)
    input_win = curses.newwin(3, max_x, max_y-3, 0)
    chat_win.scrollok(True)
    lock = threading.Lock()

    # start threads
    threading.Thread(target=receive_messages, args=(sock, chat_win, lock), daemon=True).start()
    threading.Thread(target=ack_monitor,     args=(sock, server_addr, chat_win, lock), daemon=True).start()

    while True:
        input_win.clear()
        input_win.addstr("You: ")
        input_win.refresh()
        msg = input_win.getstr().decode().strip()
        if not msg or aes_key is None:
            continue

        # Build JSON chat object
        message_id_counter += 1
        mid = str(message_id_counter)
        payload_obj = {"type": "chat", "id": mid, "username": username, "text": msg}
        plaintext = json.dumps(payload_obj)
        enc_b64   = encrypt_with_aes(aes_key, plaintext)  # returns base64 str
        packet    = pack_message(TYPE_DATA, FLAG_ENCRYPTED, enc_b64.encode())

        # Send and track
        sock.sendto(packet, server_addr)
        pending_acks[mid]    = (packet, time.time(), 0)
        message_status[mid] = "[SENT]"
        logging.info(f"Sent Msg {mid}: type=DATA enc FLAG, len={len(enc_b64)}")
        with lock:
            chat_win.addstr(f"[STATUS] Msg {mid} → [SENT]\n")
            chat_win.refresh()

if __name__ == "__main__":
    uname = input("Enter your username: ").strip()
    curses.wrapper(curses_client, uname)
