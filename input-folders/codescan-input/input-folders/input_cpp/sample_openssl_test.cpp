#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <cstring>

#define AES_KEY_SIZE 32  // 256-bit key
#define AES_IV_SIZE 16   // 128-bit IV

// Function to print bytes in hexadecimal
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

// AES-256-CBC Encryption
bool aes_encrypt(const unsigned char* plaintext, int plaintext_len,
                 const unsigned char* key, const unsigned char* iv,
                 unsigned char* ciphertext, int& ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return false;

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        return false;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        return false;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES-256-CBC Decryption
bool aes_decrypt(const unsigned char* ciphertext, int ciphertext_len,
                 const unsigned char* key, const unsigned char* iv,
                 unsigned char* plaintext, int& plaintext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return false;

    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        return false;
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        return false;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// SHA-256 Hashing
void sha256_hash(const unsigned char* data, size_t len, unsigned char* hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);
}

// RSA Key Generation, Encryption, and Decryption
RSA* generate_rsa_key() {
    int bits = 2048;
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, bits, bne, NULL);
    BN_free(bne);
    return rsa;
}

// RSA Encryption
int rsa_encrypt(RSA* rsa, const unsigned char* plaintext, int plaintext_len,
                unsigned char* ciphertext) {
    return RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);
}

// RSA Decryption
int rsa_decrypt(RSA* rsa, const unsigned char* ciphertext, int ciphertext_len,
                unsigned char* plaintext) {
    return RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, RSA_PKCS1_OAEP_PADDING);
}

int main() {
    // --- AES Encryption/Decryption ---
    unsigned char key[AES_KEY_SIZE], iv[AES_IV_SIZE];
    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_IV_SIZE);

    const char* message = "Hello, OpenSSL!";
    unsigned char ciphertext[128], decryptedtext[128];
    int ciphertext_len, decryptedtext_len;

    std::cout << "Original message: " << message << std::endl;

    if (aes_encrypt((unsigned char*)message, strlen(message), key, iv, ciphertext, ciphertext_len)) {
        std::cout << "AES Encrypted: ";
        print_hex(ciphertext, ciphertext_len);
    }

    if (aes_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext, decryptedtext_len)) {
        decryptedtext[decryptedtext_len] = '\0';  // Null-terminate the string
        std::cout << "AES Decrypted: " << decryptedtext << std::endl;
    }

    // --- SHA-256 Hashing ---
    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256_hash((unsigned char*)message, strlen(message), hash);
    std::cout << "SHA-256 Hash: ";
    print_hex(hash, SHA256_DIGEST_LENGTH);

    // --- RSA Encryption/Decryption ---
    RSA* rsa_key = generate_rsa_key();
    unsigned char rsa_ciphertext[256], rsa_decryptedtext[256];

    int rsa_ciphertext_len = rsa_encrypt(rsa_key, (unsigned char*)message, strlen(message), rsa_ciphertext);
    if (rsa_ciphertext_len != -1) {
        std::cout << "RSA Encrypted: ";
        print_hex(rsa_ciphertext, rsa_ciphertext_len);
    }

    int rsa_decryptedtext_len = rsa_decrypt(rsa_key, rsa_ciphertext, rsa_ciphertext_len, rsa_decryptedtext);
    if (rsa_decryptedtext_len != -1) {
        rsa_decryptedtext[rsa_decryptedtext_len] = '\0';  // Null-terminate
        std::cout << "RSA Decrypted: " << rsa_decryptedtext << std::endl;
    }

    RSA_free(rsa_key);
    return 0;
}
