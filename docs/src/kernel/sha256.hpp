#pragma once
#include <vector>
#include <cstdint>
#include <openssl/sha.h>

class SHA256 {
public:
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& input) {
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, input.data(), input.size());
        SHA256_Final(hash.data(), &sha256);
        return hash;
    }

    static std::vector<uint8_t> double_hash(const std::vector<uint8_t>& input) {
        return hash(hash(input));
    }
}; 