#pragma once
#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include <bitset>
#include "sha256.hpp"
#include "sha512_hmac.hpp"
#include "common.hpp"
#include <openssl/evp.h>
#include <stdexcept>

class BIP39 {
public:
    static constexpr size_t ENTROPY_BYTES = 16;  // 128 bits
    static constexpr size_t CHECKSUM_BITS = 4;   // Para 128 bits de entropia
    static constexpr size_t WORD_COUNT = 12;     // 12 palavras para 128 bits
    
    // Estrutura para armazenar o estado da geração da frase mnemônica
    struct MnemonicState {
        uint32_t indices[WORD_COUNT];
        uint8_t entropy[ENTROPY_BYTES];
        uint8_t checksum;
    };

    // Gerar índices das palavras a partir de um número
    static void generate_indices(uint64_t seed_number, uint32_t* indices) {
        // Converter o número da seed para entropia
        uint8_t entropy[ENTROPY_BYTES];
        for(size_t i = 0; i < ENTROPY_BYTES; i++) {
            entropy[i] = (seed_number >> (i * 8)) & 0xFF;
        }

        // Calcular checksum
        uint8_t checksum = get_checksum_byte(entropy);

        // Combinar entropia e checksum
        uint32_t combined[WORD_COUNT];
        size_t bit_index = 0;

        for(size_t i = 0; i < WORD_COUNT; i++) {
            uint32_t word_index = 0;
            for(size_t j = 0; j < 11; j++) {  // Cada palavra usa 11 bits
                size_t byte_idx = bit_index / 8;
                size_t bit_offset = bit_index % 8;

                uint32_t bit;
                if(byte_idx < ENTROPY_BYTES) {
                    bit = (entropy[byte_idx] >> (7 - bit_offset)) & 1;
                } else {
                    bit = (checksum >> (7 - bit_offset)) & 1;
                }

                word_index = (word_index << 1) | bit;
                bit_index++;
            }
            indices[i] = word_index;
        }
    }

    // Verificar se os índices são válidos
    static bool verify_indices(const uint32_t* indices) {
        for(size_t i = 0; i < WORD_COUNT; i++) {
            if(indices[i] >= 2048) return false;  // 2048 é o tamanho do wordlist BIP39
        }
        return true;
    }

    // Gerar seed a partir da frase mnemônica
    static std::vector<uint8_t> generate_seed(const std::string& mnemonic, const std::string& passphrase = "") {
        std::string salt = "mnemonic" + passphrase;
        std::vector<uint8_t> seed(64);

        if (PKCS5_PBKDF2_HMAC(
            mnemonic.c_str(),
            mnemonic.length(),
            reinterpret_cast<const unsigned char*>(salt.c_str()),
            salt.length(),
            2048,
            EVP_sha512(),
            64,
            seed.data()
        ) != 1) {
            throw std::runtime_error("Falha ao gerar seed BIP39");
        }

        return seed;
    }

    // Converter índices para frase mnemônica
    static void indices_to_mnemonic(const uint32_t* indices, 
                                  const std::vector<std::string>& wordlist,
                                  std::string& mnemonic) {
        mnemonic.clear();
        for(size_t i = 0; i < WORD_COUNT; i++) {
            if(i > 0) mnemonic += " ";
            mnemonic += wordlist[indices[i]];
        }
    }

    // Calcular checksum
    static uint8_t get_checksum_byte(const uint8_t* entropy) {
        auto hash = SHA256::hash(std::vector<uint8_t>(entropy, entropy + ENTROPY_BYTES));
        return hash[0];
    }

    static bool verify_checksum(const std::vector<uint8_t>& entropy) {
        // Calcular o checksum usando SHA256
        auto hash = SHA256::hash(entropy);
        
        // Verificar os primeiros bits do hash (depende do tamanho da entropy)
        size_t checksum_bits = entropy.size() * 8 / 32;
        uint8_t checksum_byte = hash[0];
        uint8_t mask = (1 << checksum_bits) - 1;
        
        return (checksum_byte & mask) == (entropy.back() & mask);
    }

    static std::vector<uint8_t> words_to_entropy(const std::vector<std::string>& words,
                                               const std::vector<std::string>& wordlist) {
        std::vector<uint8_t> entropy((words.size() * 11 - 8) / 8);
        size_t bit_index = 0;

        for (const auto& word : words) {
            // Encontrar índice da palavra
            auto it = std::find(wordlist.begin(), wordlist.end(), word);
            if (it == wordlist.end()) {
                throw std::runtime_error("Palavra inválida: " + word);
            }

            uint16_t index = std::distance(wordlist.begin(), it);

            // Adicionar 11 bits do índice à entropy
            for (int i = 10; i >= 0; --i) {
                if (bit_index / 8 < entropy.size()) {
                    uint8_t bit = (index >> i) & 1;
                    entropy[bit_index / 8] |= bit << (7 - (bit_index % 8));
                }
                bit_index++;
            }
        }

        return entropy;
    }

private:
    // Funções auxiliares para manipulação de bits
    static uint32_t get_bits(const uint8_t* data, size_t start, size_t length) {
        uint32_t result = 0;
        size_t end = start + length;
        
        for(size_t i = start; i < end; i++) {
            size_t byte_idx = i / 8;
            size_t bit_idx = 7 - (i % 8);
            
            result = (result << 1) | ((data[byte_idx] >> bit_idx) & 1);
        }
        
        return result;
    }

    static void set_bits(uint8_t* data, size_t start, size_t length, uint32_t value) {
        size_t end = start + length;
        
        for(size_t i = start; i < end; i++) {
            size_t byte_idx = i / 8;
            size_t bit_idx = 7 - (i % 8);
            
            if(value & (1 << (end - i - 1))) {
                data[byte_idx] |= (1 << bit_idx);
            } else {
                data[byte_idx] &= ~(1 << bit_idx);
            }
        }
    }
};

#ifndef BIP39_HPP
#define BIP39_HPP

// Estrutura para armazenar o par de chaves
struct KeyPair {
    std::string address;
    std::string wif;
};

// Funções para manipulação de chaves
std::vector<uint8_t> bip39_mnemonic_to_seed(const std::string& mnemonic);
KeyPair generate_key_pair(const std::vector<uint8_t>& seed);

class BIP39Utils {
public:
    // Converter mnemônico para seed
    static std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic) {
        // Validar palavras
        std::vector<std::string> words = split_mnemonic(mnemonic);
        for (const auto& word : words) {
            if (!is_valid_word(word)) {
                throw std::runtime_error("Palavra inválida: " + word);
            }
        }
        
        // Gerar seed
        std::vector<uint8_t> seed(64);
        if (!generate_seed(mnemonic, seed)) {
            throw std::runtime_error("Falha ao gerar seed BIP39");
        }
        
        return seed;
    }

private:
    // Funções auxiliares
    static std::vector<std::string> split_mnemonic(const std::string& mnemonic);
    static bool is_valid_word(const std::string& word);
    static bool generate_seed(const std::string& mnemonic, std::vector<uint8_t>& seed);
};

#endif // BIP39_HPP 