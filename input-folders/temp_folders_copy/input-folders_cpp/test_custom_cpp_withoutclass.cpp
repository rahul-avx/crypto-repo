#include <iostream>
#include <string>
#include <vector>
#include <cstring>

// Custom XOR hash function
void custom_hash(const char* input, size_t length, char* output, size_t output_size) {
    memset(output, 0, output_size);
    for (size_t i = 0; i < length; ++i) {
        output[i % output_size] ^= input[i];
    }
}

// Simple XOR encryption (symmetric)
void custom_encrypt(const char* plaintext, char* ciphertext, const char* key, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ciphertext[i] = plaintext[i] ^ key[i % strlen(key)];
    }
}

// Secure comparison (constant-time)
bool secure_compare(const char* a, const char* b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

int main() {
    const char* message = "hello world";
    const char* key = "secretkey";
    size_t len = strlen(message);

    char hash_output[8];
    custom_hash(message, len, hash_output, sizeof(hash_output));
    
    std::cout << "Custom Hash: ";
    for (char c : hash_output) {
        printf("%02x", (unsigned char)c);
    }
    std::cout << std::endl;

    std::vector<char> encrypted(len);
    custom_encrypt(message, encrypted.data(), key, len);

    std::cout << "Encrypted: ";
    for (char c : encrypted) {
        printf("%02x", (unsigned char)c);
    }
    std::cout << std::endl;

    std::vector<char> decrypted(len);
    custom_encrypt(encrypted.data(), decrypted.data(), key, len); // XOR again to decrypt

    std::cout << "Decrypted: " << std::string(decrypted.begin(), decrypted.end()) << std::endl;

    bool is_equal = secure_compare(message, decrypted.data(), len);
    std::cout << "Secure compare result: " << (is_equal ? "match" : "no match") << std::endl;

    return 0;
}
