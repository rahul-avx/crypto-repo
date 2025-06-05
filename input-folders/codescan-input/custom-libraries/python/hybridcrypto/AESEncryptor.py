from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class AESEncryptor:
    def __init__(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)

    def encrypt_data(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        encryptor = cipher.encryptor()
        padded_data = data + ' ' * (16 - len(data) % 16)
        return encryptor.update(padded_data.encode()) + encryptor.finalize()

