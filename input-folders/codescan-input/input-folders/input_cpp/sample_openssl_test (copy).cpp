#include "CryptoLib.h"

CryptoLib::CryptoLib(const std::string& key) : key(key) {}

std::string CryptoLib::encrypt(const std::string& plaintext) {
    return xorCipher(plaintext);
}

std::string CryptoLib::decrypt(const std::string& ciphertext) {
    return xorCipher(ciphertext);
}

std::string CryptoLib::xorCipher(const std::string& data) {
    std::string result = data;
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

