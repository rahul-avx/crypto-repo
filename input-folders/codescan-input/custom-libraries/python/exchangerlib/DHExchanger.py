from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

class DHExchanger:
    def __init__(self):
        self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_secret(self, peer_public_key_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        shared_key = self.private_key.exchange(peer_public_key)
        return shared_key.hex()

