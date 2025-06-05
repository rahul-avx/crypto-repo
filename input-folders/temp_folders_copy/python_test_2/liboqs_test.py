import oqs

algorithm = 'Kyber512'  # Implies key size ~512 bits security
with oqs.KeyEncapsulation(algorithm) as kem:
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)
    print(f"Using PQC algorithm {algorithm} with estimated classical security level: 128 bits")
