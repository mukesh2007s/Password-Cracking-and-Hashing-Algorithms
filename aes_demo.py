# AES (GCM) demo with password-based key derivation (PBKDF2)
# Requires: pycryptodome
#
# Run:
#   python aes_demo.py
#
# It will print: original text, encrypted token (base64), and decrypted text.
#
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

def derive_key_from_password(password: str, salt: bytes, iterations: int = 200_000, dklen: int = 32) -> bytes:
    """
    Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.
    - password: user-provided password string
    - salt: random salt (at least 16 bytes)
    - iterations: PBKDF2 iterations (security parameter)
    - dklen: derived key length in bytes (32 => 256-bit)
    """
    return PBKDF2(password, salt, dkLen=dklen, count=iterations)

def aes_gcm_encrypt(plaintext: str, password: str) -> str:
    """
    Encrypts plaintext using AES-256-GCM with a key derived from password.
    Returns a base64-encoded token that includes: salt | nonce | tag | ciphertext
    """
    salt = get_random_bytes(16)           # protect against precomputed attacks
    key = derive_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)   # random nonce generated internally
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    token = salt + cipher.nonce + tag + ciphertext
    return base64.b64encode(token).decode("utf-8")

def aes_gcm_decrypt(token_b64: str, password: str) -> str:
    """
    Decrypts a base64-encoded token produced by aes_gcm_encrypt.
    Expects: salt(16) | nonce(16 or 12) | tag(16) | ciphertext(...)
    """
    raw = base64.b64decode(token_b64)
    salt = raw[:16]
    # Try nonce length 16 then 12 for compatibility
    for nonce_len in (16, 12):
        try:
            nonce = raw[16:16+nonce_len]
            tag = raw[16+nonce_len:16+nonce_len+16]
            ciphertext = raw[16+nonce_len+16:]
            key = derive_key_from_password(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8")
        except (ValueError, KeyError):
            continue
    raise ValueError("Decryption failed. Incorrect password or invalid token.")

if __name__ == "__main__":
    message = input()
    password = "StrongPassword@123"  # For demo; in real use, get this from user input securely.

    print("=== AES-GCM Demo ===")
    print("Original :", message)

    token = aes_gcm_encrypt(message, password)
    print("Encrypted (base64 token):", token)

    recovered = aes_gcm_decrypt(token, password)
    print("Decrypted :", recovered)
