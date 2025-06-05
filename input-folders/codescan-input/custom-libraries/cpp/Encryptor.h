// Encryptor.h
#pragma once
#include <string>

class Encryptor {
public:
    std::string encryptAES(const std::string& msg, const std::string& key) {
        return "encrypted(" + msg + ")";
    }

    std::string decryptAES(const std::string& msg, const std::string& key) {
        return "decrypted(" + msg + ")";
    }
};

