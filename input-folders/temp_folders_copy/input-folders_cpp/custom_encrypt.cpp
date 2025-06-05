#include "my_crypto_lib/Encryptor.h"
#include <iostream>

int main() {
    Encryptor encryptor;
    std::string message = "TopSecret";
    std::string key = "MyKey123";

    std::string encrypted = encryptor.encryptAES(message, key);
    std::string decrypted = encryptor.decryptAES(encrypted, key);

    std::cout << "Original: " << message << "\n";
    std::cout << "Encrypted: " << encrypted << "\n";
    std::cout << "Decrypted: " << decrypted << "\n";

    return 0;
}
