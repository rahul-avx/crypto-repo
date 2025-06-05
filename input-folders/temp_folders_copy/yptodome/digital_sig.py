from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# Load RSA keys from files
with open('private.pem', 'rb') as f:
    private_key = RSA.import_key(f.read())

with open('public.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())

# Sign data
def sign_data(data, private_key):
    hash_object = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(hash_object)
    return signature

# Verify signature
def verify_signature(data, signature, public_key):
    hash_object = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(hash_object, signature)
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature is invalid.")

# Test digital signature
data = b"Message to sign"
signature = sign_data(data, private_key)
print("Signature:", signature)

verify_signature(data, signature, public_key)
