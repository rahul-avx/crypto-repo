#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <iostream>

void test_rsa() {
    // RSA encryption example
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);
    std::cout << "RSA key generated\n";
    RSA_free(rsa);
    BN_free(bn);
}

void test_aes() {
    // AES encryption example
    AES_KEY aes_key;
    unsigned char key[16] = "1234567890abcdef";
    unsigned char iv[16] = "1234567890abcdef";
    unsigned char data[16] = "Hello, AES!";
    unsigned char encrypted[16];

    AES_set_encrypt_key(key, 128, &aes_key);
    AES_cbc_encrypt(data, encrypted, 16, &aes_key, iv, AES_ENCRYPT);
    std::cout << "AES encryption done\n";
}

int main() {
    test_rsa();
    test_aes();
    return 0;
}
