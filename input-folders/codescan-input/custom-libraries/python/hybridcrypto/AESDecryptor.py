from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AESDecryptor:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def decrypt_data(self, encrypted_data):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted.decode().strip()

