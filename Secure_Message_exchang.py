from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
import os

# ------------------ Symmetric Encryption ------------------

def sym_enc(message: str, key: bytes, iv: bytes) -> bytes:
    """
    Encrypts a message using AES-CBC with PKCS7 padding.
    """
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def sym_dec(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    """
    Decrypts a ciphertext using AES-CBC with PKCS7 unpadding.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# ------------------ HMAC for Integrity ------------------

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Computes HMAC using SHA-256.
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    """
    Verifies HMAC tag.
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except Exception:
        return False

# ------------------ Authenticated Encryption ------------------

def authenticated_encrypt(message: str, session_key: bytes, iv: bytes) -> tuple:
    """
    Encrypt-then-MAC: Encrypts the message and computes HMAC over ciphertext.
    Returns (ciphertext, hmac_tag)
    """
    ciphertext = sym_enc(message, session_key, iv)
    tag = compute_hmac(session_key, ciphertext)
    return ciphertext, tag

def authenticated_decrypt(ciphertext: bytes, tag: bytes, session_key: bytes, iv: bytes) -> str:
    """
    Verifies HMAC and decrypts the ciphertext.
    """
    if not verify_hmac(session_key, ciphertext, tag):
        raise ValueError("Integrity check failed. HMAC does not match.")
    return sym_dec(ciphertext, session_key, iv)

# ------------------ Demo ------------------

if __name__ == "__main__":
    print("=== Secure Communication Demo ===")

    # Manual input of session key and IV
    session_key_hex = input("Enter 32-byte session key (hex): ")
    iv_hex = input("Enter 16-byte IV (hex): ")

    session_key = bytes.fromhex(session_key_hex)
    iv = bytes.fromhex(iv_hex)

    message = input("Enter message to send from Alice to Bob: ")

    # Alice encrypts and authenticates
    ciphertext, tag = authenticated_encrypt(message, session_key, iv)
    print("\n--- Alice Sends ---")
    print("Ciphertext (hex):", ciphertext.hex())
    print("HMAC Tag (hex):", tag.hex())

    # Bob receives and decrypts
    try:
        decrypted = authenticated_decrypt(ciphertext, tag, session_key, iv)
        print("\n--- Bob Receives ---")
        print("Decrypted Message:", decrypted)
    except ValueError as e:
        print("Decryption failed:", str(e))