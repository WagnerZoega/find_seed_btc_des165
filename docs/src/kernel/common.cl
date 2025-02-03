#ifndef COMMON_CL
#define COMMON_CL

// Macros para operações SHA512
#define CH(x,y,z) ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define SIGMA0(x) (rotate(x, 28UL) ^ rotate(x, 34UL) ^ rotate(x, 39UL))
#define SIGMA1(x) (rotate(x, 14UL) ^ rotate(x, 18UL) ^ rotate(x, 41UL))
#define sigma0(x) (rotate(x, 1UL) ^ rotate(x, 8UL) ^ (x >> 7))
#define sigma1(x) (rotate(x, 19UL) ^ rotate(x, 61UL) ^ (x >> 6))

// Rotações e shifts
#define ROTR64(x,n) ((x >> n) | (x << (64 - n)))
#define SHR(x,n)    (x >> n)

// Funções de utilidade
uint64_t swap64(uint64_t x) {
    x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
    x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
    return (x << 32) | (x >> 32);
}

uint32_t swap32(uint32_t x) {
    return ((x << 24) & 0xff000000) |
           ((x << 8)  & 0x00ff0000) |
           ((x >> 8)  & 0x0000ff00) |
           ((x >> 24) & 0x000000ff);
}

#endif // COMMON_CL 