#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define RSA_KEY_BITS 2048

void handleErrors() {
    printf("An error occurred.\n");
}

RSA *generate_RSA_keypair() {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    if (!BN_set_word(e, RSA_F4)) handleErrors();
    if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, e, NULL)) handleErrors();
    BN_free(e);
    return rsa;
}

int rsa_encrypt(RSA *rsa, unsigned char *plaintext, unsigned char *ciphertext) {
    return RSA_public_encrypt(strlen((char *)plaintext), plaintext, ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);
}

int rsa_decrypt(RSA *rsa, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    return RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, RSA_PKCS1_OAEP_PADDING);
}

int main() {
    RSA *rsa = generate_RSA_keypair();
    unsigned char plaintext[] = "Hello, OpenSSL RSA!";
    unsigned char ciphertext[256];
    unsigned char decryptedtext[256];

    int ciphertext_len = rsa_encrypt(rsa, plaintext, ciphertext);
    int decrypted_len = rsa_decrypt(rsa, ciphertext, ciphertext_len, decryptedtext);

    decryptedtext[decrypted_len] = '\0';
    printf("Decrypted text: %s\n", decryptedtext);

    RSA_free(rsa);
    return 0;
}
