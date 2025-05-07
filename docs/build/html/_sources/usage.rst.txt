Usage
=====

Run the server, then one or more clients to chat.

1. **Start the Server**  
   .. code-block:: bash

      python3 server_grad.py

   Expected log:

   .. code-block:: text

      2025-05-06 20:39:26,584 [INFO] Server listening on 0.0.0.0:12345

2. **Start a Client**  
   .. code-block:: bash

      python3 client_grad.py

   - Enter your **username** when prompted.  
   - RSA keypair is generated and sent to server.  
   - AES session key is returned (RSA-encrypted) and stored.  
   - **Secure channel established** and chat UI appears.

3. **Chat**  
   - Type your message at the prompt and press Enter.  
   - Client shows `[SENT]`, then `[DELIVERED]` (or `[FAILED]` after retries).  
   - Incoming messages from peers display as `username: text`.
