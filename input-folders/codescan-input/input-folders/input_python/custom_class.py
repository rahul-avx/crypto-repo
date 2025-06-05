from pythonlib import cryptoclass
from hybridcrypto import AESEncryptor, AESDecryptor
from signaturelib import RSASigner
from hashlib import SecureHash
from exchangerlib import DHExchanger
from hmaclib import HMACProcessor
from kdf_library import KeyDeriver

def main():
    # --- Key Generation ---
    crypto = cryptoclass()
    crypto.generate_key()
    print(f"Generated RSA key: {crypto.get_key()}")

    # --- Encryption and Decryption using AES ---
    aes_encryptor = AESEncryptor()
    aes_decryptor = AESDecryptor()
    plaintext = "Encrypt this message!"
    ciphertext = aes_encryptor.encrypt_data(plaintext)
    print(f"Encrypted: {ciphertext}")
    decrypted = aes_decryptor.decrypt_data(ciphertext)
    print(f"Decrypted: {decrypted}")

    # --- Signing Data ---
    signer = RSASigner()
    signature = signer.sign_data(plaintext)
    print(f"Signature: {signature}")

    # --- Hashing Data ---
    hasher = SecureHash()
    hashed = hasher.hash_value(plaintext)
    print(f"Hashed: {hashed}")

    # --- Message Authentication Code ---
    mac_engine = HMACProcessor()
    mac = mac_engine.compute_mac(plaintext)
    print(f"MAC: {mac}")

    # --- Key Exchange ---
    exchanger = DHExchanger()
    shared_key = exchanger.exchange_keys("peerPublicKeyXYZ")
    print(f"Shared key: {shared_key}")

    # --- Key Derivation ---
    kdf = KeyDeriver()
    derived_key = kdf.derive_key("somePassword123")
    print(f"Derived Key: {derived_key}")

if __name__ == "__main__":
    main()

