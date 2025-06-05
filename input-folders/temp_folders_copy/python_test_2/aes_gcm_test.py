from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key_size_bits = 128
key = get_random_bytes(key_size_bits // 8)
cipher = AES.new(key, AES.MODE_GCM)
print(f"AES key size: {len(key)*8} bits")
