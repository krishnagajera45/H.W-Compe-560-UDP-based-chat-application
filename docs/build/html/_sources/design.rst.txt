Cryptographic Design
====================

.. list-table::
   :header-rows: 1

   * - Mechanism
     - Description
   * - **RSA (2048-bit)**
     - Exchanges unique AES-128 session keys with each client securely.
   * - **AES-128 CBC**
     - Encrypts chat messages; uses a fresh IV and PKCS7 padding.
   * - **HMAC-SHA256**
     - Authenticates every AES-encrypted payload to prevent tampering.
   * - **Base64 Encoding**
     - Encodes binary ciphertext and keys for safe transmission over UDP.
   * - **Application-Layer ACKs**
     - Implements reliability on top of UDP with IDs and retransmissions.
