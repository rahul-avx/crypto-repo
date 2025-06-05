from crypto_class import CryptoClass

def main():
    # Initialize with a new key
    crypto = CryptoClass()

    # Original message
    message = "This is a secret message."
    print(f"Original: {message}")

    # Encrypt the message
    encrypted = crypto.encrypt(message)
    print(f"Encrypted: {encrypted}")

    # Decrypt the message
    decrypted = crypto.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")

    # Display the key used
    print(f"Key: {crypto.get_key()}")

if __name__ == "__main__":
    main()
