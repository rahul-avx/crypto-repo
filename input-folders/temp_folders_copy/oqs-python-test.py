import oqs
# Print available algorithms
print("Available KEM algorithms:")
print(oqs.get_enabled_KEM_mechanisms())
# Choose a post-quantum algorithm (e.g., Kyber-1024)
algorithm = 'Kyber1024'
# Create a KEM (Key Encapsulation Mechanism) object
kem = oqs.KeyEncapsulation(algorithm)
# Generate a keypair (public key and private key)
print(f"\nGenerating keypair using {algorithm}...")
public_key = kem.generate_keypair()
# Encapsulate (encrypt) a shared secret using the public key
print("Encapsulating shared secret...")
ciphertext, shared_secret_encapsulated = kem.encap_secret(public_key)
print(f"Ciphertext: {ciphertext}")
print(f"Shared secret (encapsulated): {shared_secret_encapsulated}")
# Decapsulate (decrypt) the shared secret using the private key
print("Decapsulating shared secret...")
shared_secret_decapsulated = kem.decap_secret(ciphertext)
print(f"Shared secret (decapsulated): {shared_secret_decapsulated}")
# Verify if the shared secrets match
if shared_secret_encapsulated == shared_secret_decapsulated:
    print("Success! The shared secret matches.")
else:
    print("Failure! The shared secrets do not match.")
# Clean up
kem.free()
