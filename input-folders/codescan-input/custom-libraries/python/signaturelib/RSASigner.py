from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class RSASigner:
    def __init__(self, private_key):
        self.private_key = private_key

    def sign_data(self, data):
        return self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

