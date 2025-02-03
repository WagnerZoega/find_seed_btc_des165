#ifndef COMMON_HPP
#define COMMON_HPP

#include <cstdint>
#include <cstring>
#include <array>
#include <vector>

class Common {
public:
    // Funções de manipulação de strings
    static size_t strlen(const uint8_t* str) {
        return std::strlen(reinterpret_cast<const char*>(str));
    }

    static bool strcmp(const uint8_t* str1, const uint8_t* str2) {
        return std::strcmp(reinterpret_cast<const char*>(str1),
                          reinterpret_cast<const char*>(str2)) == 0;
    }

    // Conversão de array de uint64_t para string
    static void ulong_to_hex(const uint64_t* input, 
                            uint32_t input_len,
                            uint8_t* output) {
        static const char hex_chars[] = "0123456789abcdef";
        
        for(uint32_t i = 0; i < input_len; i++) {
            uint64_t val = input[i];
            for(int j = 15; j >= 0; j--) {
                output[i * 16 + j] = hex_chars[val & 0xF];
                val >>= 4;
            }
        }
        output[input_len * 16] = '\0';
    }

    // Conversão de array de uint64_t para buffer de caracteres
    static void ulong_to_char_buffer(const uint64_t* input,
                                   uint32_t count,
                                   uint8_t* output) {
        size_t pos = 0;
        for(uint32_t i = 0; i < count; i++) {
            uint64_t val = input[i];
            for(int j = 7; j >= 0; j--) {
                uint8_t byte = (val >> (j * 8)) & 0xFF;
                if(byte != 0) {
                    output[pos++] = byte;
                }
            }
        }
        output[pos] = '\0';
    }

    // Rotação de bits para direita (32 bits)
    static inline uint32_t rotr32(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    // Rotação de bits para direita (64 bits)
    static inline uint64_t rotr64(uint64_t x, uint32_t n) {
        return (x >> n) | (x << (64 - n));
    }

    // Funções de endianness
    static inline uint32_t swap32(uint32_t x) {
        return ((x & 0xFF000000) >> 24) |
               ((x & 0x00FF0000) >> 8)  |
               ((x & 0x0000FF00) << 8)  |
               ((x & 0x000000FF) << 24);
    }

    static inline uint64_t swap64(uint64_t x) {
        return ((x & 0xFF00000000000000ULL) >> 56) |
               ((x & 0x00FF000000000000ULL) >> 40) |
               ((x & 0x0000FF0000000000ULL) >> 24) |
               ((x & 0x000000FF00000000ULL) >> 8)  |
               ((x & 0x00000000FF000000ULL) << 8)  |
               ((x & 0x0000000000FF0000ULL) << 24) |
               ((x & 0x000000000000FF00ULL) << 40) |
               ((x & 0x00000000000000FFULL) << 56);
    }

    // Funções de preenchimento de buffer
    static void memset_zero(void* ptr, size_t len) {
        std::memset(ptr, 0, len);
    }

    static void memcpy_offset(void* dst, const void* src, 
                            size_t len, size_t offset) {
        uint8_t* dst_bytes = static_cast<uint8_t*>(dst) + offset;
        std::memcpy(dst_bytes, src, len);
    }

    // Funções de comparação segura (tempo constante)
    static bool secure_compare(const void* a, const void* b, size_t len) {
        const uint8_t* a_bytes = static_cast<const uint8_t*>(a);
        const uint8_t* b_bytes = static_cast<const uint8_t*>(b);
        uint8_t result = 0;
        
        for(size_t i = 0; i < len; i++) {
            result |= a_bytes[i] ^ b_bytes[i];
        }
        
        return result == 0;
    }

    // Funções de manipulação de bits
    static uint32_t count_leading_zeros(uint32_t x) {
        if(x == 0) return 32;
        
        uint32_t n = 0;
        if((x & 0xFFFF0000) == 0) { n += 16; x <<= 16; }
        if((x & 0xFF000000) == 0) { n += 8;  x <<= 8;  }
        if((x & 0xF0000000) == 0) { n += 4;  x <<= 4;  }
        if((x & 0xC0000000) == 0) { n += 2;  x <<= 2;  }
        if((x & 0x80000000) == 0) { n += 1;  x <<= 1;  }
        
        return n;
    }

    static uint32_t count_trailing_zeros(uint32_t x) {
        if(x == 0) return 32;
        
        uint32_t n = 0;
        if((x & 0x0000FFFF) == 0) { n += 16; x >>= 16; }
        if((x & 0x000000FF) == 0) { n += 8;  x >>= 8;  }
        if((x & 0x0000000F) == 0) { n += 4;  x >>= 4;  }
        if((x & 0x00000003) == 0) { n += 2;  x >>= 2;  }
        if((x & 0x00000001) == 0) { n += 1;  x >>= 1;  }
        
        return n;
    }
};

// Macros para operações SHA512
#define CH(x,y,z) ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define ROTR64(x,n) ((x >> n) | (x << (64 - n)))
#define SHR(x,n)    (x >> n)

// Funções SHA512
#define SIGMA0(x)   (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39))
#define SIGMA1(x)   (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41))
#define sigma0(x)   (ROTR64(x,1)  ^ ROTR64(x,8)  ^ SHR(x,7))
#define sigma1(x)   (ROTR64(x,19) ^ ROTR64(x,61) ^ SHR(x,6))

// Funções de utilidade
uint64_t swap64(uint64_t x);
uint32_t swap32(uint32_t x);

#endif // COMMON_HPP 