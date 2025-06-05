# Filename: pqcrypto_mceliece_encrypt.py

from pqcrypto.kem.mceliece348864 import generate_keypair, encapsulate, decapsulate

# Generate a public/private keypair
public_key, private_key = generate_keypair()

# Encapsulate a shared secret (encrypt)
ciphertext, shared_secret_encapsulated = encapsulate(public_key)

print(f"Ciphertext: {ciphertext}")
print(f"Shared Secret (encapsulated): {shared_secret_encapsulated}")

# Decapsulate the shared secret (decrypt)
shared_secret_decapsulated = decapsulate(ciphertext, private_key)

print(f"Shared Secret (decapsulated): {shared_secret_decapsulated}")

# Check if the encapsulated and decapsulated shared secrets are equal
assert shared_secret_encapsulated == shared_secret_decapsulated
