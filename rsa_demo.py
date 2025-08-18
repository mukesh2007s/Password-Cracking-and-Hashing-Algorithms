# RSA (OAEP) demo with user input
# Requires: pycryptodome
#
# Run:
#   python rsa_demo.py
#
# It generates a 2048-bit RSA keypair (private.pem, public.pem),
# takes user input, encrypts with the public key, and decrypts with the private key.

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_rsa_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

def load_public_key(path: str) -> RSA.RsaKey:
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def load_private_key(path: str) -> RSA.RsaKey:
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def rsa_encrypt(plaintext: str, public_key: RSA.RsaKey) -> str:
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(ciphertext).decode("utf-8")

def rsa_decrypt(cipher_b64: str, private_key: RSA.RsaKey) -> str:
    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(cipher_b64)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode("utf-8")

if __name__ == "__main__":
    print("=== RSA (OAEP) Demo ===")

    # Generate keys (only if they don't exist yet)
    try:
        public_key = load_public_key("public.pem")
        private_key = load_private_key("private.pem")
        print("Loaded existing keys: private.pem, public.pem")
    except FileNotFoundError:
        priv, pub = generate_rsa_keypair(bits=2048)
        save_key("private.pem", priv)
        save_key("public.pem", pub)
        print("Generated new keys: private.pem, public.pem")
        public_key = load_public_key("public.pem")
        private_key = load_private_key("private.pem")

    # Get input from user
    message = input("Enter a message to encrypt: ")
    print("Original :", message)

    # Encrypt with public key
    enc = rsa_encrypt(message, public_key)
    print("Encrypted (base64):", enc)

    # Decrypt with private key
    dec = rsa_decrypt(enc, private_key)
    print("Decrypted :", dec)

    print("\nNote: RSA is suited for small messages. For large data, use AES and encrypt the AES key with RSA (hybrid).")
