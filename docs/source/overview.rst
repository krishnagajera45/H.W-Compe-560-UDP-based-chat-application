Overview
========

This secure UDP chat application enables multiple clients to exchange encrypted messages
in real time via a central server. It demonstrates:

- **UDP socket programming** in Python  
- **Hybrid encryption** (RSA-2048 for key exchange + AES-128-CBC + HMAC-SHA256 for messages)  
- **Message authentication** with HMAC  
- **Reliable delivery** over UDP via application-level ACKs and retries  
- **Terminal UI** built using curses  
