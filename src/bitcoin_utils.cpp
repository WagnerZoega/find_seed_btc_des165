#include "bitcoin_utils.hpp"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>

std::vector<uint8_t> bip39_mnemonic_to_seed(const std::string& mnemonic) {
    std::vector<uint8_t> seed(64);
    // Usar PBKDF2 para gerar a seed
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.length(),
                      (const unsigned char*)"mnemonic", 8,
                      2048, EVP_sha512(),
                      64, seed.data());
    return seed;
}

KeyPair generate_key_pair(const std::vector<uint8_t>& seed) {
    KeyPair pair;
    
    // Usar a função existente para derivar a chave privada
    std::vector<uint8_t> private_key = BitcoinUtils::derive_private_key(seed);
    
    // Gerar WIF usando a função existente
    pair.wif = BitcoinUtils::private_key_to_wif(private_key);
    
    // Gerar endereço Bitcoin usando a função existente
    pair.address = BitcoinUtils::derive_address(private_key);
    
    return pair;
}