#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <iostream>

void test_rsa() {
    using namespace CryptoPP;

    // Generate RSA keys
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;

    privateKey.GenerateRandomWithKeySize(rng, 2048);
    publicKey = RSA::PublicKey(privateKey);

    std::string message = "Hello, RSA!";

    // Encrypt the message
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    std::string ciphertext;
    StringSource(message, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext)
        )
    );

    // Decrypt the message
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    std::string recovered;
    StringSource(ciphertext, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(recovered)
        )
    );

    std::cout << "Original Message: " << message << std::endl;
    std::cout << "Recovered Message: " << recovered << std::endl;
}

void test_aes() {
    using namespace CryptoPP;

    // AES encryption
    AutoSeededRandomPool rng;
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(key, sizeof(key));
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Hello, AES!";
    std::string ciphertext, recovered;

    // Encrypt the message
    try {
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, sizeof(key), iv);

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryption,
                new StringSink(ciphertext)
            )
        );
    } catch (const Exception& e) {
        std::cerr << "Encryption Error: " << e.what() << std::endl;
        return;
    }

    // Decrypt the message
    try {
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, sizeof(key), iv);

        StringSource(ciphertext, true,
            new StreamTransformationFilter(decryption,
                new StringSink(recovered)
            )
        );
    } catch (const Exception& e) {
        std::cerr << "Decryption Error: " << e.what() << std::endl;
        return;
    }

    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Recovered: " << recovered << std::endl;
}

int main() {
    std::cout << "Testing RSA:" << std::endl;
    test_rsa();

    std::cout << "\nTesting AES:" << std::endl;
    test_aes();

    return 0;
}
