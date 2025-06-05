from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

KEY_SIZE = 256 // 8  # Convert bits to bytes
key = os.urandom(KEY_SIZE)
iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
print(f"AES key size in bits: {len(key) * 8}")
