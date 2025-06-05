#include "Encryptor.h"
#include <iostream>
// Simulate AES encryption (not secure! just a placeholder)

Encryptor::Encryptor() {}

std::string Encryptor::encryptAES(const std::string& plaintext, const std::string& key) {
    // Placeholder: reverse string to simulate "encryption"
    std::string encrypted = std::string(plaintext.rbegin(), plaintext.rend());
    return encrypted;
}

std::string Encryptor::decryptAES(const std::string& ciphertext, const std::string& key) {
    // Placeholder: reverse back
    std::string decrypted = std::string(ciphertext.rbegin(), ciphertext.rend());
    return decrypted;
}
