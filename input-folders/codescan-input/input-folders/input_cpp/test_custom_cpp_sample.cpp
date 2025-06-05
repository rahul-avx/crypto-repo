#include <iostream>
#include <string>
#include <vector>

class CustomCryptoLib {
public:
    CustomCryptoLib(const std::string& key) : key(key) {}

    std::string encrypt(const std::string& plaintext) {
        return xorCipher(plaintext);
    }

    std::string decrypt(const std::string& ciphertext) {
        return xorCipher(ciphertext);
    }

    std::string simpleHash(const std::string& input) {
        unsigned int hash = 0;
        for (char c : input) {
            hash = hash * 101 + c;
        }
        return std::to_string(hash);
    }

    std::string base64Encode(const std::string& data) {
        // Dummy base64 - not real encoding
        return "base64(" + data + ")";
    }

    bool verify(const std::string& data, const std::string& signature) {
        return simpleHash(data) == signature;
    }

private:
    std::string xorCipher(const std::string& data) {
        std::string result = data;
        for (size_t i = 0; i < data.size(); ++i) {
            result[i] ^= key[i % key.size()];
        }
        return result;
    }

    std::string key;
};

int main() {
    CustomCryptoLib crypto("myKey");

    std::string text = "SecretMessage";
    std::string enc = crypto.encrypt(text);
    std::string dec = crypto.decrypt(enc);
    std::string hash = crypto.simpleHash(text);
    std::string encoded = crypto.base64Encode(text);
    bool verified = crypto.verify(text, hash);

    std::cout << "Encrypted: " << enc << "\n";
    std::cout << "Decrypted: " << dec << "\n";
    std::cout << "Hash: " << hash << "\n";
    std::cout << "Base64: " << encoded << "\n";
    std::cout << "Verified: " << std::boolalpha << verified << "\n";

    return 0;
}
