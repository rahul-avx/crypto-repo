from Crypto.Hash import SHA256

# Hash data using SHA-256
def hash_data(data):
    hash_object = SHA256.new(data)
    return hash_object.hexdigest()

# Test hashing
data = b"Data to be hashed"
hashed_value = hash_data(data)
print("Original Data:", data)
print("SHA-256 Hash:", hashed_value)
