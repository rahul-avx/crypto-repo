from Crypto.PublicKey import RSA

KEY_SIZE = 2048
key = RSA.generate(KEY_SIZE)
key = RSA.generate(KEY_SIZE)
print(f"Generated RSA key with size: {key.size_in_bits()} bits")
