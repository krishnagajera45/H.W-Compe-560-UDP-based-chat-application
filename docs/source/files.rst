Project Files
=============

.. list-table::
   :header-rows: 1

   * - File Name
     - Purpose
   * - server_grad.py
     - UDP server (key exchange, decrypt/broadcast, ACKs)
   * - client_grad.py
     - UDP client (RSA/AES key exchange, encrypt/decrypt, UI, retransmit)
   * - crypto_utils_grad.py
     - Cryptographic helpers (RSA, AES, HMAC)
   * - README.md
     - User-facing documentation & run instructions
   * - chat.log
     - Client log of `[SENT]`, `[DELIVERED]`, `[FAILED]`
   * - server_chat.log
     - Server log of key exchanges, messages, broadcasts
