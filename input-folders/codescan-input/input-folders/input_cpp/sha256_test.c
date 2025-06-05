#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

void print_hash(unsigned char *hash) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

int main() {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char data[] = "Hello, OpenSSL SHA-256!";
    
    SHA256((unsigned char *)data, strlen(data), hash);
    
    printf("SHA-256 Hash: ");
    print_hash(hash);
    
    return 0;
}
