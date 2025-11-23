from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

# ==================== Key Derivation ====================
def derive_key(password, salt=None, iterations=100000):
    """
    Derive a secure 256-bit key from a password using PBKDF2
    """
    if salt is None:
        salt = get_random_bytes(16)
    key = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    return key, salt


# ==================== GCM Mode (Recommended) ====================
def encrypt_AES_GCM(plaintext, password):
    """
    AES-GCM Encryption (Authenticated)
    Output = base64(salt + nonce + tag + ciphertext)
    """
    key, salt = derive_key(password)
    nonce = get_random_bytes(12)  # GCM standard

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

    result = salt + nonce + tag + ciphertext
    return base64.b64encode(result).decode("utf-8")


def decrypt_AES_GCM(encrypted_b64, password):
    """
    AES-GCM Decryption with authentication
    """
    data = base64.b64decode(encrypted_b64)

    if len(data) < 44:
        raise ValueError("Ciphertext too short")

    salt = data[:16]
    nonce = data[16:28]
    tag = data[28:44]
    ciphertext = data[44:]

    key, _ = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


# ==================== CBC Mode ====================
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def encrypt_AES_CBC(plaintext, password):
    key, salt = derive_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8")))
    result = salt + iv + ciphertext

    return base64.b64encode(result).decode("utf-8")


def decrypt_AES_CBC(encrypted_b64, password):
    data = base64.b64decode(encrypted_b64)

    if len(data) < 32:
        raise ValueError("Ciphertext too short")

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key, _ = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext_padded = cipher.decrypt(ciphertext)
    return unpad(plaintext_padded).decode("utf-8")


# ==================== TEST ====================
if __name__ == "__main__":
    password = "mazin_secret_2024"
    message = "Hello Mazin! This is a secure message 🔐"

    print("\n=== GCM TEST ===")
    enc_gcm = encrypt_AES_GCM(message, password)
    print("Encrypted:", enc_gcm)
    print("Decrypted:", decrypt_AES_GCM(enc_gcm, password))

    print("\n=== CBC TEST ===")
    enc_cbc = encrypt_AES_CBC(message, password)
    print("Encrypted:", enc_cbc)
    print("Decrypted:", decrypt_AES_CBC(enc_cbc, password))
