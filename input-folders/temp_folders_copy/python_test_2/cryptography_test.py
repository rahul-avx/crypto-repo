from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 4096  # in bits

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=KEY_SIZE,
)
public_key = private_key.public_key()
print(f"Generated RSA key with size: {KEY_SIZE}")
