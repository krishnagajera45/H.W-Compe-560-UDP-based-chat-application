from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hmac
import hashlib

def generate_rsa_keypair():
    """
    Generate a 2048-bit RSA key pair.

    :return: (private_key_bytes, public_key_bytes) in PEM format.
    """
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def encrypt_with_rsa(public_key_bytes, message_bytes):
    """
    Encrypt a message with an RSA public key using OAEP.

    :param public_key_bytes: RSA public key bytes.
    :param message_bytes: Plaintext bytes to encrypt.
    :return: RSA-encrypted ciphertext bytes.
    """
    pub_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message_bytes)

def decrypt_with_rsa(private_key_bytes, encrypted_bytes):
    """
    Decrypt an RSA ciphertext with the corresponding private key using OAEP.

    :param private_key_bytes: RSA private key bytes.
    :param encrypted_bytes: Ciphertext bytes to decrypt.
    :return: Decrypted plaintext bytes.
    """
    priv_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(encrypted_bytes)

def generate_aes_key():
    """
    Generate a random 128-bit AES key.

    :return: 16-byte AES key.
    """
    return get_random_bytes(16)

def encrypt_with_aes(aes_key, plaintext):
    """
    Encrypt plaintext using AES-128-CBC and HMAC-SHA256 authentication.

    Generates a random IV for each encryption. Returns a base64 string containing the HMAC tag, IV, and ciphertext.

    :param aes_key: 16-byte AES key.
    :param plaintext: Plaintext string to encrypt.
    :return: Base64-encoded authenticated ciphertext.
    """
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    enc_data = iv + ciphertext
    tag = hmac.new(aes_key, enc_data, hashlib.sha256).digest()
    return base64.b64encode(tag + enc_data).decode()

def decrypt_with_aes(aes_key, b64_message):
    """
    Decrypt a base64-encoded AES-128-CBC ciphertext with HMAC-SHA256 verification.

    :param aes_key: 16-byte AES key.
    :param b64_message: Base64 string with HMAC tag, IV, and ciphertext.
    :return: Decrypted plaintext string.
    :raises ValueError: If authentication fails or padding is invalid.
    """
    raw = base64.b64decode(b64_message)
    tag, enc_data = raw[:32], raw[32:]
    if not hmac.compare_digest(tag, hmac.new(aes_key, enc_data, hashlib.sha256).digest()):
        raise ValueError("HMAC verification failed!")
    iv, ciphertext = enc_data[:16], enc_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
