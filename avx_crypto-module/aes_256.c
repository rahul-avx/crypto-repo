#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define AES_KEY_SIZE 32  // AES-256
#define AES_IV_SIZE 12   // GCM IV size
#define TAG_SIZE 16      // GCM Tag size

void handleErrors() {
    printf("An error occurred.\n");
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    if (!ctx || !EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        handleErrors();

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
        handleErrors();

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *tag, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len, ret;

    if (!ctx || !EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        handleErrors();

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag))
        handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    return ret > 0 ? (plaintext_len + len) : -1;  // -1 means authentication failed
}

int main() {
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char plaintext[] = "Hello, OpenSSL AES!";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_IV_SIZE);

    int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext, tag);
    int decrypted_len = decrypt(ciphertext, ciphertext_len, key, iv, tag, decryptedtext);

    decryptedtext[decrypted_len] = '\0';
    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}
