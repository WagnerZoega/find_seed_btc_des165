#pragma once
#include <vector>
#include <cstdint>
#include <openssl/hmac.h>
#include <openssl/evp.h>

class HMAC_SHA512 {
public:
    static std::vector<uint8_t> hash(const uint8_t* key, size_t key_len,
                                   const uint8_t* data, size_t data_len) {
        std::vector<uint8_t> output(64); // SHA512 produz 512 bits = 64 bytes
        unsigned int out_len = 64;

        HMAC_CTX* ctx = HMAC_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Falha ao criar contexto HMAC");
        }

        // Inicializar HMAC com SHA512 e a chave
        if (!HMAC_Init_ex(ctx, key, key_len, EVP_sha512(), nullptr)) {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("Falha ao inicializar HMAC");
        }

        // Adicionar os dados
        if (!HMAC_Update(ctx, data, data_len)) {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("Falha ao atualizar HMAC");
        }

        // Finalizar e obter o hash
        if (!HMAC_Final(ctx, output.data(), &out_len)) {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("Falha ao finalizar HMAC");
        }

        HMAC_CTX_free(ctx);
        return output;
    }

    // Versão que aceita vetores como entrada
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& data) {
        return hash(key.data(), key.size(), data.data(), data.size());
    }

    // Versão que aceita string como chave
    static std::vector<uint8_t> hash(const std::string& key,
                                   const std::vector<uint8_t>& data) {
        return hash(reinterpret_cast<const uint8_t*>(key.c_str()),
                   key.size(),
                   data.data(),
                   data.size());
    }
}; 