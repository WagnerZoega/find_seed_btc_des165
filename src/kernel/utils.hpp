#ifndef KERNEL_UTILS_HPP
#define KERNEL_UTILS_HPP

#include <cstdint>

namespace kernel {
namespace utils {

// Definições de rotação e deslocamento de bits
inline uint32_t ROTR32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

inline uint64_t ROTR64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

inline uint32_t SHR(uint32_t x, int n) {
    return x >> n;
}

// Funções sigma para SHA256/512
inline uint32_t sigma0(uint32_t x) {
    return ROTR32(x, 1) ^ ROTR32(x, 8) ^ SHR(x, 7);
}

inline uint32_t sigma1(uint32_t x) {
    return ROTR32(x, 19) ^ ROTR32(x, 61) ^ SHR(x, 6);
}

} // namespace utils
} // namespace kernel

#endif // KERNEL_UTILS_HPP 