from cryptography.hazmat.primitives import hashes

class SecureHash:
    def hash_value(self, data):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data.encode())
        return digest.finalize().hex()

