from Crypto.PublicKey import DSA

key_size = 2048
key = DSA.generate(key_size)
print(f"Generated DSA key with size: {key.size_in_bits()} bits")
