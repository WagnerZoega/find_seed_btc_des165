// bitcoin_utils.hpp
#pragma once
#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <thread>
#include <iostream>
#include "../src/kernel/sha256.hpp"
#include "../src/kernel/sha512_hmac.hpp"

// Estrutura para armazenar par de chaves
struct KeyPair {
    std::string address;
    std::string wif;
};

// Funções para manipulação de Bitcoin
std::vector<uint8_t> bip39_mnemonic_to_seed(const std::string& mnemonic);
KeyPair generate_key_pair(const std::vector<uint8_t>& seed);

class BitcoinUtils {
public:
    // Converter bytes para string hexadecimal
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        static const char hex_chars[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(bytes.size() * 2);
        
        for(uint8_t byte : bytes) {
            hex.push_back(hex_chars[byte >> 4]);
            hex.push_back(hex_chars[byte & 0x0F]);
        }
        
        return hex;
    }

    // Converter string hexadecimal para bytes
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        bytes.reserve(hex.length() / 2);
        
        for(size_t i = 0; i < hex.length(); i += 2) {
            uint8_t byte = (hex_value(hex[i]) << 4) | hex_value(hex[i + 1]);
            bytes.push_back(byte);
        }
        
        return bytes;
    }

    // Verificar se um endereço Bitcoin é válido
    static bool is_valid_address(const std::string& address) {
        std::vector<uint8_t> decoded = base58_decode(address);
        if(decoded.size() != 25) return false;
        
        // Verificar checksum
        std::vector<uint8_t> without_checksum(decoded.begin(), decoded.end() - 4);
        auto hash1 = sha256(without_checksum);
        auto hash2 = sha256(hash1);
        
        return std::equal(hash2.begin(), hash2.begin() + 4, 
                         decoded.end() - 4);
    }

    // Gerar endereço Bitcoin a partir da chave privada
    static std::string derive_address(const std::vector<uint8_t>& private_key) {
        try {
            // 1. Gerar chave pública comprimida (33 bytes: 0x02/0x03 + x)
            std::vector<uint8_t> public_key = private_to_public(private_key, true); // true = comprimida
            
            // 2. SHA256 da chave pública
            auto sha256_hash = sha256(public_key);
            
            // 3. RIPEMD160 do resultado SHA256
            auto hash160 = ripemd160(sha256_hash);
            
            // 4. Versão + Hash160 (1 + 20 bytes)
            std::vector<uint8_t> address_bytes;
            address_bytes.reserve(21);
            address_bytes.push_back(0x00); // Versão para mainnet
            address_bytes.insert(address_bytes.end(), hash160.begin(), hash160.end());
            
            // 5. Double SHA256 para checksum
            auto checksum = sha256(sha256(address_bytes));
            
            // 6. Adicionar os primeiros 4 bytes do checksum
            address_bytes.insert(address_bytes.end(), checksum.begin(), checksum.begin() + 4);
            
            // 7. Base58 encode
            return base58_encode(address_bytes);
        } catch (const std::exception& e) {
            std::cerr << "Erro ao gerar endereço Bitcoin: " << e.what() << std::endl;
            return "";
        }
    }

    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_path(
        const std::vector<uint8_t>& master_private_key,
        const std::vector<uint8_t>& master_chain_code,
        const std::vector<uint32_t>& path) {
        
        std::vector<uint8_t> private_key = master_private_key;
        std::vector<uint8_t> chain_code = master_chain_code;
        
        for (uint32_t index : path) {
            std::tie(private_key, chain_code) = derive_key(private_key, chain_code, index);
        }
        
        return {private_key, chain_code};
    }

    // Mover para a seção pública
    static std::vector<uint8_t> derive_private_key(const std::vector<uint8_t>& seed) {
        try {
            // 1. Gerar master key usando HMAC-SHA512 com "Bitcoin seed"
            const std::string key = "Bitcoin seed";
            auto master = hmac_sha512(
                reinterpret_cast<const uint8_t*>(key.c_str()),
                key.size(),
                seed.data(),
                seed.size()
            );

            // 2. Split em master key e chain code
            std::vector<uint8_t> master_key(master.begin(), master.begin() + 32);
            std::vector<uint8_t> chain_code(master.begin() + 32, master.end());

            // 3. Derivar caminho m/44'/0'/0'/0/0 (BIP44 completo)
            auto current_key = master_key;
            auto current_chain = chain_code;

            // Derivar cada nível do caminho
            std::vector<uint32_t> path = {
                0x8000002C,  // 44' (hardened)
                0x80000000,  // 0'  (hardened)
                0x80000000,  // 0'  (hardened)
                0,           // 0   (normal)
                0            // 0   (normal)
            };

            for (uint32_t index : path) {
                std::vector<uint8_t> data;
                data.reserve(37);

                if (index & 0x80000000) {
                    // Hardened derivation
                    data.push_back(0x00);
                    data.insert(data.end(), current_key.begin(), current_key.end());
                } else {
                    // Normal derivation
                    auto pub_key = private_to_public(current_key, true); // true = compressed
                    data.insert(data.end(), pub_key.begin(), pub_key.end());
                }

                // Append index
                data.push_back((index >> 24) & 0xFF);
                data.push_back((index >> 16) & 0xFF);
                data.push_back((index >> 8) & 0xFF);
                data.push_back(index & 0xFF);

                // HMAC-SHA512
                auto i = hmac_sha512(
                    current_chain.data(),
                    current_chain.size(),
                    data.data(),
                    data.size()
                );

                // Split into IL and IR
                std::vector<uint8_t> IL(i.begin(), i.begin() + 32);
                current_chain = std::vector<uint8_t>(i.begin() + 32, i.end());

                // child_key = (IL + parent_key) mod n
                BIGNUM* bn_IL = BN_bin2bn(IL.data(), IL.size(), nullptr);
                BIGNUM* bn_parent = BN_bin2bn(current_key.data(), current_key.size(), nullptr);
                BIGNUM* bn_n = BN_new();
                BN_CTX* ctx = BN_CTX_new();

                EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
                EC_GROUP_get_order(group, bn_n, ctx);

                BIGNUM* bn_child = BN_new();
                BN_mod_add(bn_child, bn_IL, bn_parent, bn_n, ctx);

                // Convert to bytes
                current_key.resize(32, 0);
                BN_bn2bin(bn_child, current_key.data() + (32 - BN_num_bytes(bn_child)));

                // Cleanup
                BN_free(bn_IL);
                BN_free(bn_parent);
                BN_free(bn_n);
                BN_free(bn_child);
                BN_CTX_free(ctx);
                EC_GROUP_free(group);
            }

            return current_key;
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Erro na derivação: ") + e.what());
        }
    }

    // Converter chave privada para WIF
    static std::string private_key_to_wif(const std::vector<uint8_t>& private_key) {
        try {
            // 1. Versão (0x80) + Chave Privada + Flag de Compressão (0x01)
            std::vector<uint8_t> wif_bytes;
            wif_bytes.reserve(34);
            
            wif_bytes.push_back(0x80);  // Mainnet private key
            wif_bytes.insert(wif_bytes.end(), private_key.begin(), private_key.end());
            wif_bytes.push_back(0x01);  // Compressed public key flag
            
            // 2. Double SHA256 checksum
            auto checksum = sha256(sha256(wif_bytes));
            wif_bytes.insert(wif_bytes.end(), checksum.begin(), checksum.begin() + 4);
            
            // 3. Base58 encode
            return base58_encode(wif_bytes);
        } catch (const std::exception& e) {
            std::cerr << "Erro ao converter chave privada para WIF: " << e.what() << std::endl;
            return "";
        }
    }

private:
    static uint8_t hex_value(char hex_digit) {
        if(hex_digit >= '0' && hex_digit <= '9') return hex_digit - '0';
        if(hex_digit >= 'a' && hex_digit <= 'f') return hex_digit - 'a' + 10;
        if(hex_digit >= 'A' && hex_digit <= 'F') return hex_digit - 'A' + 10;
        throw std::invalid_argument("Caractere hexadecimal inválido");
    }

    static std::vector<uint8_t> base58_decode(const std::string& str) {
        static const char* base58_chars = 
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        
        std::vector<uint8_t> result;
        result.reserve(str.length());
        
        // Converter de base58 para base256
        for(char c : str) {
            const char* pos = strchr(base58_chars, c);
            if(pos == nullptr) {
                throw std::invalid_argument("Caractere base58 inválido");
            }
            
            int value = pos - base58_chars;
            for(size_t i = result.size(); i > 0; i--) {
                value += result[i-1] * 58;
                result[i-1] = value & 0xFF;
                value >>= 8;
            }
            
            if(value > 0) {
                result.insert(result.begin(), static_cast<uint8_t>(value));
            }
        }
        
        // Adicionar zeros iniciais do endereço original
        for(size_t i = 0; i < str.length() && str[i] == '1'; i++) {
            result.insert(result.begin(), 0);
        }
        
        return result;
    }

    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& input) {
        return SHA256::hash(input);
    }

    static std::vector<uint8_t> ripemd160(const std::vector<uint8_t>& input) {
        std::vector<uint8_t> hash(RIPEMD160_DIGEST_LENGTH);
        RIPEMD160_CTX ripemd160;
        RIPEMD160_Init(&ripemd160);
        RIPEMD160_Update(&ripemd160, input.data(), input.size());
        RIPEMD160_Final(hash.data(), &ripemd160);
        return hash;
    }

    static std::string base58_encode(const std::vector<uint8_t>& input) {
        static const char* ALPHABET = 
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        
        // Converter para big number e fazer a codificação
        std::string result;
        std::vector<uint8_t> digits(input.begin(), input.end());
        
        // Calcular o tamanho da string resultante
        result.reserve(input.size() * 138 / 100 + 1);
        
        // Converter para base58
        while (!digits.empty()) {
            uint32_t remainder = 0;
            for (size_t i = 0; i < digits.size(); i++) {
                uint32_t digit256 = (uint32_t)digits[i];
                uint32_t temp = remainder * 256 + digit256;
                digits[i] = (uint8_t)(temp / 58);
                remainder = temp % 58;
            }
            
            result.insert(0, 1, ALPHABET[remainder]);
            
            // Remover zeros à esquerda
            while (!digits.empty() && digits.front() == 0) {
                digits.erase(digits.begin());
            }
        }
        
        // Adicionar '1' para cada zero no início do input
        for (size_t i = 0; i < input.size() && input[i] == 0; i++) {
            result.insert(0, 1, '1');
        }
        
        return result;
    }

    static std::vector<uint8_t> hmac_sha512(const uint8_t* key, size_t key_len,
                                          const uint8_t* data, size_t data_len) {
        return HMAC_SHA512::hash(key, key_len, data, data_len);
    }
    
    static std::vector<uint8_t> private_to_public(const std::vector<uint8_t>& private_key, bool compressed = true) {
        std::vector<uint8_t> public_key(compressed ? 33 : 65);
        
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!ec_key) {
            throw std::runtime_error("Falha ao criar EC_KEY");
        }
        
        BIGNUM* priv_bn = BN_bin2bn(private_key.data(), private_key.size(), nullptr);
        if (!priv_bn) {
            EC_KEY_free(ec_key);
            throw std::runtime_error("Falha ao converter chave privada");
        }
        
        // Definir a chave privada
        if (!EC_KEY_set_private_key(ec_key, priv_bn)) {
            BN_free(priv_bn);
            EC_KEY_free(ec_key);
            throw std::runtime_error("Falha ao definir chave privada");
        }
        
        // Calcular o ponto público
        EC_POINT* pub_point = EC_POINT_new(EC_KEY_get0_group(ec_key));
        if (!pub_point) {
            BN_free(priv_bn);
            EC_KEY_free(ec_key);
            throw std::runtime_error("Falha ao criar ponto EC");
        }
        
        if (!EC_POINT_mul(EC_KEY_get0_group(ec_key), pub_point, priv_bn, nullptr, nullptr, nullptr)) {
            EC_POINT_free(pub_point);
            BN_free(priv_bn);
            EC_KEY_free(ec_key);
            throw std::runtime_error("Falha na multiplicação do ponto EC");
        }
        
        // Serializar a chave pública no formato comprimido
        point_conversion_form_t form = compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
        size_t len = EC_POINT_point2oct(EC_KEY_get0_group(ec_key), pub_point, form,
                                      public_key.data(), public_key.size(), nullptr);
        
        if (len != public_key.size()) {
            EC_POINT_free(pub_point);
            BN_free(priv_bn);
            EC_KEY_free(ec_key);
            throw std::runtime_error("Falha ao serializar chave pública");
        }
        
        // Limpar
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        
        return public_key;
    }

    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_key(
        const std::vector<uint8_t>& parent_private_key,
        const std::vector<uint8_t>& parent_chain_code,
        uint32_t index) {
        
        std::vector<uint8_t> data;
        data.reserve(37);  // 1 + 32 + 4 bytes para o pior caso
        
        if (index & 0x80000000) {
            // Hardened derivation
            data.push_back(0x00);
            data.insert(data.end(), parent_private_key.begin(), parent_private_key.end());
        } else {
            // Normal derivation - usar chave pública comprimida
            auto pub_key = private_to_public(parent_private_key);
            data.insert(data.end(), pub_key.begin(), pub_key.end());
        }
        
        // Append index em big-endian
        data.push_back((index >> 24) & 0xFF);
        data.push_back((index >> 16) & 0xFF);
        data.push_back((index >> 8) & 0xFF);
        data.push_back(index & 0xFF);
        
        // HMAC-SHA512
        auto i = hmac_sha512(
            parent_chain_code.data(),
            parent_chain_code.size(),
            data.data(),
            data.size()
        );
        
        // Split into left and right parts
        std::vector<uint8_t> left(i.begin(), i.begin() + 32);
        std::vector<uint8_t> right(i.begin() + 32, i.end());
        
        // Calcular child_key = (IL + parent_key) mod n
        BIGNUM* IL = BN_bin2bn(left.data(), left.size(), nullptr);
        BIGNUM* parent = BN_bin2bn(parent_private_key.data(), parent_private_key.size(), nullptr);
        BIGNUM* n = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        
        // Get curve order
        EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        EC_GROUP_get_order(group, n, ctx);
        
        // child = (IL + parent) mod n
        BIGNUM* child = BN_new();
        BN_mod_add(child, IL, parent, n, ctx);
        
        // Verificar se a chave é válida
        if (BN_is_zero(child) || BN_cmp(child, n) >= 0) {
            // Se inválida, retornar erro
            BN_free(IL);
            BN_free(parent);
            BN_free(n);
            BN_free(child);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("Chave derivada inválida");
        }
        
        // Convert result back to bytes
        std::vector<uint8_t> child_private_key(32);
        int bytes = BN_num_bytes(child);
        BN_bn2bin(child, child_private_key.data() + (32 - bytes));
        
        // Clean up
        BN_free(IL);
        BN_free(parent);
        BN_free(n);
        BN_free(child);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        
        return {child_private_key, right};
    }
};