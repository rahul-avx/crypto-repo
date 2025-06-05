import oqs

sig_alg = "Dilithium2"

message = b"Post-quantum signatures are here!"

# Signer
with oqs.Signature(sig_alg) as signer:
    public_key = signer.generate_keypair()
    signature = signer.sign(message)

# Verifier
with oqs.Signature(sig_alg) as verifier:
    result = verifier.verify(message, signature, public_key)

print("Signature valid:", result)
