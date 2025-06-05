from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP521R1())
public_key = private_key.public_key()
print(f"Using EC key with curve: SECP521R1 -> ~{521} bits")
