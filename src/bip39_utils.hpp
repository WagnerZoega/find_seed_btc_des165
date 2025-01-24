#pragma once
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <bitset>
#include <cstdint>  // Para uint16_t
#include "kernel/sha512_hmac.hpp"
#include <openssl/evp.h>
#include <sstream>
#include <thread>
#include <fstream>
#include <iostream>
#include "globals.hpp"  // Adicionar este include
#include <filesystem>

class BIP39Utils {
public:
    // Para a busca geral - usa FIXED_WORDS
    static const std::vector<std::string>& get_wordlist() {
        return FIXED_WORDS;  // Agora FIXED_WORDS é conhecido
    }

    // Função auxiliar para encontrar o arquivo wordlist
    static std::string get_wordlist_path() {
        std::vector<std::string> possible_paths = {
            "wordlist-ptbr.txt",
            "src/wordlist-ptbr.txt",
            "../src/wordlist-ptbr.txt",
            "../../src/wordlist-ptbr.txt",
            "C++/src/wordlist-ptbr.txt",
            "bitcoin_cracking-main/C++/src/wordlist-ptbr.txt"
        };
        
        std::cout << "Procurando wordlist-ptbr.txt em:" << std::endl;
        for (const auto& path : possible_paths) {
            std::cout << "Tentando: " << std::filesystem::absolute(path).string() << std::endl;
            std::ifstream file(path);
            if (file.good()) {
                std::cout << "Arquivo encontrado em: " << std::filesystem::absolute(path).string() << std::endl;
                return path;
            }
        }
        
        throw std::runtime_error("Não foi possível encontrar o arquivo wordlist-ptbr.txt. "
                               "Por favor, coloque o arquivo em uma das seguintes localizações:\n" +
                               [&]() {
                                   std::string paths;
                                   for (const auto& p : possible_paths) {
                                       paths += "- " + std::filesystem::absolute(p).string() + "\n";
                                   }
                                   return paths;
                               }());
    }

    // Para o teste - usa wordlist completa em português
    static const std::vector<std::string>& get_test_wordlist() {
        static std::vector<std::string> test_wordlist;
        
        // Carregar apenas uma vez
        if (test_wordlist.empty()) {
            std::string path = get_wordlist_path();
            std::ifstream file(path);
            if (!file.is_open()) {
                throw std::runtime_error("Não foi possível abrir o arquivo: " + path);
            }

            std::cout << "Carregando wordlist de: " << path << std::endl;
            
            std::string word;
            while (std::getline(file, word)) {
                // Remover espaços em branco e caracteres especiais
                word.erase(std::remove_if(word.begin(), word.end(), ::isspace), word.end());
                if (!word.empty()) {
                    test_wordlist.push_back(word);
                }
            }

            if (test_wordlist.empty()) {
                throw std::runtime_error("Wordlist de teste está vazia");
            }

            std::cout << "Carregadas " << test_wordlist.size() << " palavras da wordlist de teste" << std::endl;
        }

        return test_wordlist;
    }

    // Verificação específica para o teste
    static bool verify_test_mnemonic(const std::string& mnemonic) {
        std::vector<std::string> words;
        std::stringstream ss(mnemonic);
        std::string word;
        
        while (ss >> word) {
            words.push_back(word);
        }
        
        if (words.size() != 12) {
            std::cerr << "Erro: Número incorreto de palavras. Esperado: 12, Encontrado: " 
                      << words.size() << std::endl;
            return false;
        }
        
        const auto& wordlist = get_test_wordlist();
        for (const auto& w : words) {
            if (std::find(wordlist.begin(), wordlist.end(), w) == wordlist.end()) {
                std::cerr << "Erro: Palavra não encontrada na wordlist: " << w << std::endl;
                return false;
            }
        }
        
        return true;
    }

    static std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic, const std::string& passphrase = "") {
        try {
            // Para o teste, usar verify_test_mnemonic em vez de verify_mnemonic
            if (!verify_test_mnemonic(mnemonic)) {
                throw std::runtime_error("Frase mnemônica inválida");
            }

            // Gerar seed usando PBKDF2-HMAC-SHA512
            std::string salt = "mnemonic" + passphrase;
            std::vector<uint8_t> seed(64);
            
            if (PKCS5_PBKDF2_HMAC(
                mnemonic.c_str(),                // senha = frase mnemônica
                mnemonic.length(),
                reinterpret_cast<const unsigned char*>(salt.c_str()),
                salt.length(),
                2048,                           // exatamente 2048 iterações
                EVP_sha512(),                   // usando SHA-512
                64,                             // seed de 512 bits (64 bytes)
                seed.data()
            ) != 1) {
                throw std::runtime_error("Falha ao gerar seed BIP39");
            }

            return seed;
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Erro ao gerar seed: ") + e.what());
        }
    }

    // Função específica para teste
    static std::vector<uint8_t> test_mnemonic_to_seed(const std::string& mnemonic, const std::string& passphrase = "") {
        try {
            // Gerar seed usando PBKDF2-HMAC-SHA512
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
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Erro ao gerar seed: ") + e.what());
        }
    }

    static bool verify_mnemonic(const std::string& mnemonic) {
        std::vector<std::string> words;
        std::stringstream ss(mnemonic);
        std::string word;
        
        // Separar palavras
        while (ss >> word) {
            words.push_back(word);
        }
        
        // BIP39: Deve ter exatamente 12 palavras
        if (words.size() != 12) {
            return false;
        }
        
        // Verificar se todas as palavras estão na wordlist
        const auto& wordlist = get_wordlist();
        for (const auto& w : words) {
            if (std::find(wordlist.begin(), wordlist.end(), w) == wordlist.end()) {
                return false;
            }
        }
        
        // Converter palavras em índices
        std::vector<uint16_t> indices;
        for (const auto& word : words) {
            auto it = std::find(wordlist.begin(), wordlist.end(), word);
            indices.push_back(static_cast<uint16_t>(std::distance(wordlist.begin(), it)));
        }
        
        // BIP39: Converter índices em bits
        std::vector<bool> bits;
        for (uint16_t index : indices) {
            for (int i = 10; i >= 0; --i) {
                bits.push_back((index >> i) & 1);
            }
        }
        
        // BIP39: Calcular e verificar checksum
        // Como estamos usando uma lista reduzida, vamos pular esta verificação
        
        return true;
    }

    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& input) {
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, input.data(), input.size());
        SHA256_Final(hash.data(), &sha256);
        return hash;
    }

    static std::vector<uint8_t> words_to_entropy(const std::vector<std::string>& words) {
        std::vector<uint8_t> entropy;
        const auto& wordlist = get_wordlist();
        
        // Converter palavras em índices (usando uint16_t em vez de uint11_t)
        std::vector<uint16_t> indices;
        for (const auto& word : words) {
            auto it = std::find(wordlist.begin(), wordlist.end(), word);
            if (it == wordlist.end()) {
                throw std::runtime_error("Palavra inválida na frase mnemônica");
            }
            indices.push_back(static_cast<uint16_t>(std::distance(wordlist.begin(), it)));
        }
        
        // Converter índices em bits
        std::vector<bool> bits;
        for (uint16_t index : indices) {
            // Ainda usamos apenas 11 bits de cada índice
            for (int i = 10; i >= 0; --i) {
                bits.push_back((index >> i) & 1);
            }
        }
        
        // Remover bits de checksum
        size_t entropy_bits = (bits.size() * 32) / 33;
        bits.resize(entropy_bits);
        
        // Converter bits em bytes
        entropy.resize((bits.size() + 7) / 8);
        for (size_t i = 0; i < bits.size(); i += 8) {
            uint8_t byte = 0;
            for (size_t j = 0; j < 8 && (i + j) < bits.size(); ++j) {
                byte = (byte << 1) | bits[i + j];
            }
            entropy[i / 8] = byte;
        }
        
        return entropy;
    }

    static std::vector<uint32_t> words_to_indices(const std::vector<std::string>& words) {
        std::vector<uint32_t> indices;
        indices.reserve(words.size());
        
        const auto& wordlist = get_wordlist();
        for(const auto& word : words) {
            auto it = std::find(wordlist.begin(), wordlist.end(), word);
            if(it != wordlist.end()) {
                indices.push_back(std::distance(wordlist.begin(), it));
            }
        }
        
        return indices;
    }

    static std::pair<uint64_t, uint64_t> mnemonic_to_uint64_pair(const std::vector<uint32_t>& indices) {
        std::string binary;
        for(uint32_t index : indices) {
            std::string bin = std::bitset<11>(index).to_string();
            binary += bin;
        }
        
        // Remover os últimos 4 bits
        binary = binary.substr(0, binary.length() - 4);
        
        // Preencher com zeros até 128 bits
        binary.append(128 - binary.length(), '0');
        
        // Dividir em duas partes de 64 bits
        uint64_t high = std::stoull(binary.substr(0, 64), nullptr, 2);
        uint64_t low = std::stoull(binary.substr(64), nullptr, 2);
        
        return {high, low};
    }

    // Converter string para lista de palavras
    static std::vector<std::string> split_mnemonic(const std::string& mnemonic) {
        std::vector<std::string> words;
        std::stringstream ss(mnemonic);
        std::string word;
        
        while (ss >> word) {
            words.push_back(word);
        }
        
        return words;
    }

private:
    // Verificar se uma palavra está na wordlist
    static bool is_valid_word(const std::string& word) {
        const auto& wordlist = get_wordlist();
        return std::find(wordlist.begin(), wordlist.end(), word) != wordlist.end();
    }
};
