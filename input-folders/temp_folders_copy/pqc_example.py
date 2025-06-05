import oqs
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def demo_oqs_key_exchange():
    print("Demo: OQS Key Exchange (CRYSTALS-Kyber)")

    # Initialize key exchange objects
    server = oqs.KeyEncapsulation("Kyber1024")
    client = oqs.KeyEncapsulation("Kyber1024")

    # Generate client public key
    client_public_key = client.generate_keypair()

    # Server encapsulates the shared secret
    ciphertext, shared_secret_server = server.encap_secret(client_public_key)

    # Client decapsulates the shared secret

    shared_secret_client = client.decap_secret(ciphertext)

    # Verify both shared secrets are identical
    assert shared_secret_server == shared_secret_client
    print("Key exchange successful! Shared secret:", shared_secret_client.hex())

def demo_pqcrypto_signature():
    print("\nDemo: PQCrypto Digital Signature (Dilithium2)")

    # Generate key pair
    public_key, secret_key = generate_keypair()

    # Sign a message
    message = b"This is a message to sign."
    signature = sign(message, secret_key)

    # Verify the signature
    if verify(message, signature,
