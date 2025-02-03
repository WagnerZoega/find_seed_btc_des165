#include "bip39_utils.hpp"

namespace BIP39Utils {
    const std::vector<std::string>& get_wordlist() {
        return FIXED_WORDS;
    }

    std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic, const std::string& passphrase) {
        try {
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

    bool verify_test_mnemonic(const std::string& mnemonic) {
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
        
        const auto& wordlist = get_wordlist();
        for (const auto& w : words) {
            if (std::find(wordlist.begin(), wordlist.end(), w) == wordlist.end()) {
                std::cerr << "Erro: Palavra não encontrada na wordlist: " << w << std::endl;
                return false;
            }
        }
        
        return true;
    }

    std::vector<uint8_t> test_mnemonic_to_seed(const std::string& mnemonic, const std::string& passphrase) {
        if (!verify_test_mnemonic(mnemonic)) {
            throw std::runtime_error("Frase mnemônica inválida");
        }
        return mnemonic_to_seed(mnemonic, passphrase);
    }

    std::vector<uint32_t> words_to_indices(const std::vector<std::string>& words) {
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

    std::pair<uint64_t, uint64_t> mnemonic_to_uint64_pair(const std::vector<uint32_t>& indices) {
        std::string binary;
        for(uint32_t index : indices) {
            std::string bin = std::bitset<11>(index).to_string();
            binary += bin;
        }
        
        binary = binary.substr(0, binary.length() - 4);
        binary.append(128 - binary.length(), '0');
        
        uint64_t high = std::stoull(binary.substr(0, 64), nullptr, 2);
        uint64_t low = std::stoull(binary.substr(64), nullptr, 2);
        
        return {high, low};
    }

    std::vector<std::string> split_mnemonic(const std::string& mnemonic) {
        std::vector<std::string> words;
        std::stringstream ss(mnemonic);
        std::string word;
        
        while (ss >> word) {
            words.push_back(word);
        }
        
        return words;
    }

    // Implemente as outras funções aqui...
} 