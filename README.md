# Password-Cracking-and-Hashing-Algorithms
 Codec Technologies - Cybersecurity internship project
# Cryptography Algorithms Implementation (AES & RSA) — Simple Demo

This mini-project shows **two fundamental cryptography techniques** using Python:

- **AES (GCM mode)** with password-based key derivation (PBKDF2)
- **RSA (OAEP)** public-key encryption

Both scripts are beginner-friendly, self-contained, and ready to run.  
Use them to encrypt/decrypt messages, take screenshots of terminal output, and publish the repo on GitHub / LinkedIn.

---

## ▶️ Quick Start

```bash
# 1) Create & activate a virtual environment (recommended)
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 2) Install dependency
pip install -r requirements.txt

# 3) Run AES demo
python aes_demo.py

# 4) Run RSA demo
python rsa_demo.py
```

> Each script prints the original message, encrypted token, and the decrypted message.

---

## 🔐 AES (GCM) — What & Why
- **AES** is a **symmetric** algorithm: the **same key** is used to encrypt and decrypt.
- We derive a 256-bit key from your **password** using **PBKDF2** with a random salt.
- We use **GCM mode**, which gives **confidentiality + integrity** (authenticity).
- The output token contains: `salt + nonce + tag + ciphertext` (Base64-encoded).

### Files
- `aes_demo.py` — Simple encrypt/decrypt demo using a password.

---

## 🔑 RSA (OAEP) — What & Why
- **RSA** is an **asymmetric** algorithm: a **public key** encrypts and a **private key** decrypts.
- We use **2048-bit** RSA keys and **OAEP** padding (secure and standard).
- The demo shows generating keys, encrypting with the **public** key, and decrypting with the **private** key.

### Files
- `rsa_demo.py` — Generates `private.pem` and `public.pem`, performs encrypt/decrypt demo.

---

## 🧪 Sample Use-Cases
- Encrypt small secrets (notes, tokens) with AES using a password you remember.
- Share your **RSA public key** so others can send you secrets that only you (with the private key) can decrypt.

---

## 📁 Project Structure
```
.
├─ aes_demo.py
├─ rsa_demo.py
├─ requirements.txt
└─ README.md
```

---

## ✅ Notes & Limits
- AES-GCM token is self-contained and safe to store/transmit.
- RSA is meant for **small messages** (a few hundred bytes). For large data, encrypt with AES and then encrypt the AES key with RSA (hybrid encryption).
- Keep your **private key** secret. Never commit it publicly unless for demo purposes only.

---

## 📸 What to capture for submission
- Terminal screenshot of running `aes_demo.py` (showing plaintext → token → decrypted text).
- Terminal screenshot of running `rsa_demo.py` (showing key generation + encrypt/decrypt output).
- Your GitHub repo link containing these files.
