// Definições e macros comuns
#define ROTR_256(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH_SHA256(x, y, z) (((x) & (y)) ^ (~(x) & (z))))
#define MAJ_SHA256(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))))
#define EP0_SHA256(x) (ROTR_256(x, 2) ^ ROTR_256(x, 13) ^ ROTR_256(x, 22))
#define EP1_SHA256(x) (ROTR_256(x, 6) ^ ROTR_256(x, 11) ^ ROTR_256(x, 25))
#define SIG0_SHA256(x) (ROTR_256(x, 7) ^ ROTR_256(x, 18) ^ ((x) >> 3))
#define SIG1_SHA256(x) (ROTR_256(x, 17) ^ ROTR_256(x, 19) ^ ((x) >> 10))

// Constantes SHA256
__constant uint K_256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

// Implementação correta de sha256_from_byte
uchar sha256_from_byte(ulong max, ulong min) {
    uint w[64] = {0};
    uint a, b, c, d, e, f, g, h, temp1, temp2;

    w[0] = (max >> 32) & 0xFFFFFFFF;
    w[1] = max & 0xFFFFFFFF;
    w[2] = (min >> 32) & 0xFFFFFFFF;
    w[3] = min & 0xFFFFFFFF;
    w[4] = 0x80000000;
    w[15] = 128;

    #pragma unroll
    for (int i = 16; i < 64; ++i) {
        w[i] = w[i - 16] + SIG0_SHA256(w[i - 15]) + w[i - 7] + SIG1_SHA256(w[i - 2]);
    }

    a = H0;
    b = H1;
    c = H2;
    d = H3;
    e = H4;
    f = H5;
    g = H6;
    h = H7;

    #pragma unroll
    for (int i = 0; i < 63; ++i) {
        temp1 = h + EP1_SHA256(e) + CH_SHA256(e, f, g) + K_256[i] + w[i];
        temp2 = EP0_SHA256(a) + MAJ_SHA256(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    temp1 = h + EP1_SHA256(e) + CH_SHA256(e, f, g) + K_256[63] + w[63];
    temp2 = EP0_SHA256(a) + MAJ_SHA256(a, b, c);
    a = temp1 + temp2;

    return (uchar)(((H0 + a) >> 24) & 0xFF);
}

// Definições e macros para SHA512
#define F1(x, y, z) (bitselect(z, y, x))
#define F0(x, y, z) (bitselect(x, y, ((x) ^ (z))))
#define rotr64(a, n) (rotate((a), (64ul - n)))

#define SHA512_S0(x) (rotr64(x, 28ul) ^ rotr64(x, 34ul) ^ rotr64(x, 39ul))
#define SHA512_S1(x) (rotr64(x, 14ul) ^ rotr64(x, 18ul) ^ rotr64(x, 41ul))

inline ulong L0(ulong x) {
    return rotr64(x, 1ul) ^ rotr64(x, 8ul) ^ (x >> 7ul);
}

inline ulong L1(ulong x) {
    return rotr64(x, 19ul) ^ rotr64(x, 61ul) ^ (x >> 6ul);
}

#define COPY_EIGHT(a, b)                                                       \
    (a)[0] = (b)[0], (a)[1] = (b)[1], (a)[2] = (b)[2], (a)[3] = (b)[3],          \
    (a)[4] = (b)[4], (a)[5] = (b)[5], (a)[6] = (b)[6], (a)[7] = (b)[7];

#define COPY_EIGHT_XOR(a, b)                                                   \
    (a)[0] ^= (b)[0];                                                            \
    (a)[1] ^= (b)[1];                                                            \
    (a)[2] ^= (b)[2];                                                            \
    (a)[3] ^= (b)[3];                                                            \
    (a)[4] ^= (b)[4];                                                            \
    (a)[5] ^= (b)[5];                                                            \
    (a)[6] ^= (b)[6];                                                            \
    (a)[7] ^= (b)[7];

#define INIT_SHA512(a)                                                         \
    (a)[0] = 0x6a09e667f3bcc908UL;                                               \
    (a)[1] = 0xbb67ae8584caa73bUL;                                               \
    (a)[2] = 0x3c6ef372fe94f82bUL;                                               \
    (a)[3] = 0xa54ff53a5f1d36f1UL;                                               \
    (a)[4] = 0x510e527fade682d1UL;                                               \
    (a)[5] = 0x9b05688c2b3e6c1fUL;                                               \
    (a)[6] = 0x1f83d9abfb41bd6bUL;                                               \
    (a)[7] = 0x5be0cd19137e2179UL;

// Implementação da função sha512_procces
void sha512_procces(ulong *message, ulong *H) {
    __private ulong A0 = H[0], A1 = H[1], A2 = H[2], A3 = H[3], A4 = H[4],
                  A5 = H[5], A6 = H[6], A7 = H[7];

    __private ulong W16 = (message[0] + L0(message[1]) + message[9] + L1(message[14]));
    __private ulong W17 = (message[1] + L0(message[2]) + message[10] + L1(message[15]));
    __private ulong W18 = (message[2] + L0(message[3]) + message[11] + L1(W16));
    __private ulong W19 = (message[3] + L0(message[4]) + message[12] + L1(W17));
    __private ulong W20 = (message[4] + L0(message[5]) + message[13] + L1(W18));
    __private ulong W21 = (message[5] + L0(message[6]) + message[14] + L1(W19));
    __private ulong W22 = message[6] + L0(message[7]) + message[15] + L1(W20);
    __private ulong W23 = message[7] + L0(message[8]) + W16 + L1(W21);
    __private ulong W24 = message[8] + L0(message[9]) + W17 + L1(W22);
    __private ulong W25 = message[9] + L0(message[10]) + W18 + L1(W23);
    __private ulong W26 = message[10] + L0(message[11]) + W19 + L1(W24);
    __private ulong W27 = message[11] + L0(message[12]) + W20 + L1(W25);
    __private ulong W28 = message[12] + L0(message[13]) + W21 + L1(W26);
    __private ulong W29 = message[13] + L0(message[14]) + W22 + L1(W27);
    __private ulong W30 = message[14] + L0(message[15]) + W23 + L1(W28);
    __private ulong W31 = message[15] + L0(W16) + W24 + L1(W29);

    __private ulong W32 = W16 + L0(W17) + W25 + L1(W30);

    // Constantes SHA512
    __constant ulong SHA512_PRIMES[80] = {
        0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL,
        0xe9b5dba58189dbbcUL, 0x3956c25bf348b538UL, 0x59f111f1b605d019UL,
        0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL, 0xd807aa98a3030242UL,
        0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
        0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL,
        0xc19bf174cf692694UL, 0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL,
        0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL, 0x2de92c6f592b0275UL,
        0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
        0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL,
        0xbf597fc7beef0ee4UL, 0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL,
        0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL,
        0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
        0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL,
        0x92722c851482353bUL, 0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL,
        0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL, 0xd192e819d6ef5218UL,
        0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
        0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL,
        0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL,
        0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL,
        0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
        0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL,
        0xc67178f2e372532bUL, 0xca273eceea26619cUL, 0xd186b8c721c0c207UL,
        0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL, 0x06f067aa72176fbaUL,
        0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
        0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL,
        0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL,
        0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
    };

    // Macro para as operações de round
    #define RoR(a, b, c, d, e, f, g, h, x, K)                                      \
    {                                                                            \
        ulong t1 = K + SHA512_S1(e) + F1(e, f, g) + x;                             \
        ulong t2 = SHA512_S0(a) + F0(a, b, c);                                     \
        h += t1;                                                                   \
        d += h;                                                                    \
        h += t2;                                                                   \
    }

    // Aplicar as 80 rounds
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[0], SHA512_PRIMES[0]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[1], SHA512_PRIMES[1]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[2], SHA512_PRIMES[2]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[3], SHA512_PRIMES[3]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[4], SHA512_PRIMES[4]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[5], SHA512_PRIMES[5]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[6], SHA512_PRIMES[6]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[7], SHA512_PRIMES[7]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[8], SHA512_PRIMES[8]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[9], SHA512_PRIMES[9]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[10], SHA512_PRIMES[10]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[11], SHA512_PRIMES[11]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[12], SHA512_PRIMES[12]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[13], SHA512_PRIMES[13]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[14], SHA512_PRIMES[14]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[15], SHA512_PRIMES[15]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W16, SHA512_PRIMES[16]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W17, SHA512_PRIMES[17]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W18, SHA512_PRIMES[18]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W19, SHA512_PRIMES[19]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W20, SHA512_PRIMES[20]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W21, SHA512_PRIMES[21]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W22, SHA512_PRIMES[22]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W23, SHA512_PRIMES[23]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W24, SHA512_PRIMES[24]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W25, SHA512_PRIMES[25]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W26, SHA512_PRIMES[26]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W27, SHA512_PRIMES[27]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W28, SHA512_PRIMES[28]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W29, SHA512_PRIMES[29]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W30, SHA512_PRIMES[30]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W31, SHA512_PRIMES[31]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W32, SHA512_PRIMES[32]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[0], SHA512_PRIMES[33]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[1], SHA512_PRIMES[34]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[2], SHA512_PRIMES[35]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[3], SHA512_PRIMES[36]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[4], SHA512_PRIMES[37]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[5], SHA512_PRIMES[38]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[6], SHA512_PRIMES[39]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[7], SHA512_PRIMES[40]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[8], SHA512_PRIMES[41]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[9], SHA512_PRIMES[42]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[10], SHA512_PRIMES[43]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[11], SHA512_PRIMES[44]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[12], SHA512_PRIMES[45]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[13], SHA512_PRIMES[46]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[14], SHA512_PRIMES[47]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[15], SHA512_PRIMES[48]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W16, SHA512_PRIMES[49]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W17, SHA512_PRIMES[50]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W18, SHA512_PRIMES[51]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W19, SHA512_PRIMES[52]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W20, SHA512_PRIMES[53]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W21, SHA512_PRIMES[54]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W22, SHA512_PRIMES[55]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W23, SHA512_PRIMES[56]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W24, SHA512_PRIMES[57]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W25, SHA512_PRIMES[58]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W26, SHA512_PRIMES[59]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W27, SHA512_PRIMES[60]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W28, SHA512_PRIMES[61]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W29, SHA512_PRIMES[62]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W30, SHA512_PRIMES[63]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W31, SHA512_PRIMES[64]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W32, SHA512_PRIMES[65]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[0], SHA512_PRIMES[66]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[1], SHA512_PRIMES[67]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[2], SHA512_PRIMES[68]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[3], SHA512_PRIMES[69]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[4], SHA512_PRIMES[70]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[5], SHA512_PRIMES[71]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[6], SHA512_PRIMES[72]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[7], SHA512_PRIMES[73]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[8], SHA512_PRIMES[74]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[9], SHA512_PRIMES[75]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[10], SHA512_PRIMES[76]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[11], SHA512_PRIMES[77]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[12], SHA512_PRIMES[78]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[13], SHA512_PRIMES[79]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[14], SHA512_PRIMES[80]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[15], SHA512_PRIMES[81]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W16, SHA512_PRIMES[82]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W17, SHA512_PRIMES[83]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W18, SHA512_PRIMES[84]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W19, SHA512_PRIMES[85]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W20, SHA512_PRIMES[86]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W21, SHA512_PRIMES[87]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W22, SHA512_PRIMES[88]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W23, SHA512_PRIMES[89]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W24, SHA512_PRIMES[90]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W25, SHA512_PRIMES[91]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W26, SHA512_PRIMES[92]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W27, SHA512_PRIMES[93]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W28, SHA512_PRIMES[94]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W29, SHA512_PRIMES[95]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W30, SHA512_PRIMES[96]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W31, SHA512_PRIMES[97]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W32, SHA512_PRIMES[98]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[0], SHA512_PRIMES[99]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[1], SHA512_PRIMES[100]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[2], SHA512_PRIMES[101]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[3], SHA512_PRIMES[102]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[4], SHA512_PRIMES[103]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[5], SHA512_PRIMES[104]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[6], SHA512_PRIMES[105]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[7], SHA512_PRIMES[106]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[8], SHA512_PRIMES[107]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[9], SHA512_PRIMES[108]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[10], SHA512_PRIMES[109]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[11], SHA512_PRIMES[110]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[12], SHA512_PRIMES[111]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[13], SHA512_PRIMES[112]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[14], SHA512_PRIMES[113]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[15], SHA512_PRIMES[114]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W16, SHA512_PRIMES[115]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W17, SHA512_PRIMES[116]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W18, SHA512_PRIMES[117]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W19, SHA512_PRIMES[118]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W20, SHA512_PRIMES[119]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W21, SHA512_PRIMES[120]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W22, SHA512_PRIMES[121]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W23, SHA512_PRIMES[122]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W24, SHA512_PRIMES[123]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W25, SHA512_PRIMES[124]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W26, SHA512_PRIMES[125]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W27, SHA512_PRIMES[126]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W28, SHA512_PRIMES[127]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W29, SHA512_PRIMES[128]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W30, SHA512_PRIMES[129]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W31, SHA512_PRIMES[130]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W32, SHA512_PRIMES[131]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[0], SHA512_PRIMES[132]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[1], SHA512_PRIMES[133]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[2], SHA512_PRIMES[134]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[3], SHA512_PRIMES[135]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[4], SHA512_PRIMES[136]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[5], SHA512_PRIMES[137]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[6], SHA512_PRIMES[138]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[7], SHA512_PRIMES[139]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[8], SHA512_PRIMES[140]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[9], SHA512_PRIMES[141]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[10], SHA512_PRIMES[142]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[11], SHA512_PRIMES[143]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[12], SHA512_PRIMES[144]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[13], SHA512_PRIMES[145]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[14], SHA512_PRIMES[146]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[15], SHA512_PRIMES[147]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W16, SHA512_PRIMES[148]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W17, SHA512_PRIMES[149]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W18, SHA512_PRIMES[150]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W19, SHA512_PRIMES[151]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W20, SHA512_PRIMES[152]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W21, SHA512_PRIMES[153]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W22, SHA512_PRIMES[154]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W23, SHA512_PRIMES[155]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W24, SHA512_PRIMES[156]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W25, SHA512_PRIMES[157]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W26, SHA512_PRIMES[158]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W27, SHA512_PRIMES[159]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W28, SHA512_PRIMES[160]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W29, SHA512_PRIMES[161]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W30, SHA512_PRIMES[162]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W31, SHA512_PRIMES[163]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W32, SHA512_PRIMES[164]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[0], SHA512_PRIMES[165]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[1], SHA512_PRIMES[166]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[2], SHA512_PRIMES[167]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[3], SHA512_PRIMES[168]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[4], SHA512_PRIMES[169]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[5], SHA512_PRIMES[170]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[6], SHA512_PRIMES[171]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[7], SHA512_PRIMES[172]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[8], SHA512_PRIMES[173]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[9], SHA512_PRIMES[174]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[10], SHA512_PRIMES[175]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[11], SHA512_PRIMES[176]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[12], SHA512_PRIMES[177]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[13], SHA512_PRIMES[178]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[14], SHA512_PRIMES[179]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[15], SHA512_PRIMES[180]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W16, SHA512_PRIMES[181]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W17, SHA512_PRIMES[182]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W18, SHA512_PRIMES[183]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W19, SHA512_PRIMES[184]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W20, SHA512_PRIMES[185]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W21, SHA512_PRIMES[186]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W22, SHA512_PRIMES[187]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W23, SHA512_PRIMES[188]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W24, SHA512_PRIMES[189]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W25, SHA512_PRIMES[190]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W26, SHA512_PRIMES[191]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W27, SHA512_PRIMES[192]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W28, SHA512_PRIMES[193]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W29, SHA512_PRIMES[194]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W30, SHA512_PRIMES[195]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W31, SHA512_PRIMES[196]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W32, SHA512_PRIMES[197]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[0], SHA512_PRIMES[198]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[1], SHA512_PRIMES[199]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[2], SHA512_PRIMES[200]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[3], SHA512_PRIMES[201]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[4], SHA512_PRIMES[202]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[5], SHA512_PRIMES[203]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[6], SHA512_PRIMES[204]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[7], SHA512_PRIMES[205]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[8], SHA512_PRIMES[206]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[9], SHA512_PRIMES[207]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[10], SHA512_PRIMES[208]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[11], SHA512_PRIMES[209]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[12], SHA512_PRIMES[210]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[13], SHA512_PRIMES[211]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[14], SHA512_PRIMES[212]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[15], SHA512_PRIMES[213]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W16, SHA512_PRIMES[214]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W17, SHA512_PRIMES[215]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W18, SHA512_PRIMES[216]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W19, SHA512_PRIMES[217]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W20, SHA512_PRIMES[218]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W21, SHA512_PRIMES[219]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W22, SHA512_PRIMES[220]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W23, SHA512_PRIMES[221]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W24, SHA512_PRIMES[222]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W25, SHA512_PRIMES[223]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W26, SHA512_PRIMES[224]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W27, SHA512_PRIMES[225]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W28, SHA512_PRIMES[226]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W29, SHA512_PRIMES[227]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W30, SHA512_PRIMES[228]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W31, SHA512_PRIMES[229]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W32, SHA512_PRIMES[230]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[0], SHA512_PRIMES[231]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[1], SHA512_PRIMES[232]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[2], SHA512_PRIMES[233]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[3], SHA512_PRIMES[234]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[4], SHA512_PRIMES[235]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[5], SHA512_PRIMES[236]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[6], SHA512_PRIMES[237]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[7], SHA512_PRIMES[238]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[8], SHA512_PRIMES[239]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[9], SHA512_PRIMES[240]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[10], SHA512_PRIMES[241]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[11], SHA512_PRIMES[242]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[12], SHA512_PRIMES[243]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[13], SHA512_PRIMES[244]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[14], SHA512_PRIMES[245]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[15], SHA512_PRIMES[246]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W16, SHA512_PRIMES[247]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W17, SHA512_PRIMES[248]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W18, SHA512_PRIMES[249]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W19, SHA512_PRIMES[250]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W20, SHA512_PRIMES[251]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W21, SHA512_PRIMES[252]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W22, SHA512_PRIMES[253]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W23, SHA512_PRIMES[254]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W24, SHA512_PRIMES[255]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W25, SHA512_PRIMES[256]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W26, SHA512_PRIMES[257]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W27, SHA512_PRIMES[258]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W28, SHA512_PRIMES[259]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W29, SHA512_PRIMES[260]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W30, SHA512_PRIMES[261]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W31, SHA512_PRIMES[262]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W32, SHA512_PRIMES[263]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[0], SHA512_PRIMES[264]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[1], SHA512_PRIMES[265]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[2], SHA512_PRIMES[266]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[3], SHA512_PRIMES[267]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[4], SHA512_PRIMES[268]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[5], SHA512_PRIMES[269]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[6], SHA512_PRIMES[270]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[7], SHA512_PRIMES[271]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[8], SHA512_PRIMES[272]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[9], SHA512_PRIMES[273]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[10], SHA512_PRIMES[274]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[11], SHA512_PRIMES[275]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[12], SHA512_PRIMES[276]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[13], SHA512_PRIMES[277]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[14], SHA512_PRIMES[278]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[15], SHA512_PRIMES[279]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W16, SHA512_PRIMES[280]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W17, SHA512_PRIMES[281]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W18, SHA512_PRIMES[282]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W19, SHA512_PRIMES[283]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W20, SHA512_PRIMES[284]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W21, SHA512_PRIMES[285]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W22, SHA512_PRIMES[286]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W23, SHA512_PRIMES[287]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W24, SHA512_PRIMES[288]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W25, SHA512_PRIMES[289]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W26, SHA512_PRIMES[290]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W27, SHA512_PRIMES[291]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W28, SHA512_PRIMES[292]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W29, SHA512_PRIMES[293]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W30, SHA512_PRIMES[294]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W31, SHA512_PRIMES[295]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W32, SHA512_PRIMES[296]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[0], SHA512_PRIMES[297]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[1], SHA512_PRIMES[298]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[2], SHA512_PRIMES[299]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[3], SHA512_PRIMES[300]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[4], SHA512_PRIMES[301]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[5], SHA512_PRIMES[302]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[6], SHA512_PRIMES[303]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[7], SHA512_PRIMES[304]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[8], SHA512_PRIMES[305]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[9], SHA512_PRIMES[306]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[10], SHA512_PRIMES[307]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[11], SHA512_PRIMES[308]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[12], SHA512_PRIMES[309]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[13], SHA512_PRIMES[310]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[14], SHA512_PRIMES[311]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[15], SHA512_PRIMES[312]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W16, SHA512_PRIMES[313]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W17, SHA512_PRIMES[314]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W18, SHA512_PRIMES[315]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W19, SHA512_PRIMES[316]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W20, SHA512_PRIMES[317]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W21, SHA512_PRIMES[318]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W22, SHA512_PRIMES[319]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W23, SHA512_PRIMES[320]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W24, SHA512_PRIMES[321]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W25, SHA512_PRIMES[322]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W26, SHA512_PRIMES[323]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W27, SHA512_PRIMES[324]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W28, SHA512_PRIMES[325]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W29, SHA512_PRIMES[326]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W30, SHA512_PRIMES[327]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W31, SHA512_PRIMES[328]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W32, SHA512_PRIMES[329]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[0], SHA512_PRIMES[330]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[1], SHA512_PRIMES[331]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[2], SHA512_PRIMES[332]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[3], SHA512_PRIMES[333]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[4], SHA512_PRIMES[334]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[5], SHA512_PRIMES[335]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[6], SHA512_PRIMES[336]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[7], SHA512_PRIMES[337]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[8], SHA512_PRIMES[338]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[9], SHA512_PRIMES[339]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[10], SHA512_PRIMES[340]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[11], SHA512_PRIMES[341]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[12], SHA512_PRIMES[342]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[13], SHA512_PRIMES[343]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[14], SHA512_PRIMES[344]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[15], SHA512_PRIMES[345]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W16, SHA512_PRIMES[346]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W17, SHA512_PRIMES[347]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W18, SHA512_PRIMES[348]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W19, SHA512_PRIMES[349]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W20, SHA512_PRIMES[350]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W21, SHA512_PRIMES[351]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W22, SHA512_PRIMES[352]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W23, SHA512_PRIMES[353]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W24, SHA512_PRIMES[354]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W25, SHA512_PRIMES[355]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W26, SHA512_PRIMES[356]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W27, SHA512_PRIMES[357]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W28, SHA512_PRIMES[358]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W29, SHA512_PRIMES[359]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W30, SHA512_PRIMES[360]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W31, SHA512_PRIMES[361]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W32, SHA512_PRIMES[362]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[0], SHA512_PRIMES[363]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[1], SHA512_PRIMES[364]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[2], SHA512_PRIMES[365]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[3], SHA512_PRIMES[366]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[4], SHA512_PRIMES[367]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[5], SHA512_PRIMES[368]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[6], SHA512_PRIMES[369]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[7], SHA512_PRIMES[370]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[8], SHA512_PRIMES[371]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[9], SHA512_PRIMES[372]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[10], SHA512_PRIMES[373]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[11], SHA512_PRIMES[374]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[12], SHA512_PRIMES[375]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[13], SHA512_PRIMES[376]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[14], SHA512_PRIMES[377]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[15], SHA512_PRIMES[378]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W16, SHA512_PRIMES[379]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W17, SHA512_PRIMES[380]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W18, SHA512_PRIMES[381]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W19, SHA512_PRIMES[382]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W20, SHA512_PRIMES[383]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W21, SHA512_PRIMES[384]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W22, SHA512_PRIMES[385]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W23, SHA512_PRIMES[386]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W24, SHA512_PRIMES[387]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W25, SHA512_PRIMES[388]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W26, SHA512_PRIMES[389]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W27, SHA512_PRIMES[390]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W28, SHA512_PRIMES[391]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W29, SHA512_PRIMES[392]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W30, SHA512_PRIMES[393]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W31, SHA512_PRIMES[394]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W32, SHA512_PRIMES[395]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[0], SHA512_PRIMES[396]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[1], SHA512_PRIMES[397]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[2], SHA512_PRIMES[398]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[3], SHA512_PRIMES[399]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[4], SHA512_PRIMES[400]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[5], SHA512_PRIMES[401]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[6], SHA512_PRIMES[402]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[7], SHA512_PRIMES[403]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[8], SHA512_PRIMES[404]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[9], SHA512_PRIMES[405]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[10], SHA512_PRIMES[406]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[11], SHA512_PRIMES[407]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[12], SHA512_PRIMES[408]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[13], SHA512_PRIMES[409]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[14], SHA512_PRIMES[410]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[15], SHA512_PRIMES[411]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W16, SHA512_PRIMES[412]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W17, SHA512_PRIMES[413]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W18, SHA512_PRIMES[414]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W19, SHA512_PRIMES[415]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W20, SHA512_PRIMES[416]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W21, SHA512_PRIMES[417]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W22, SHA512_PRIMES[418]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W23, SHA512_PRIMES[419]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W24, SHA512_PRIMES[420]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W25, SHA512_PRIMES[421]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W26, SHA512_PRIMES[422]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W27, SHA512_PRIMES[423]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W28, SHA512_PRIMES[424]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W29, SHA512_PRIMES[425]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W30, SHA512_PRIMES[426]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W31, SHA512_PRIMES[427]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W32, SHA512_PRIMES[428]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[0], SHA512_PRIMES[429]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[1], SHA512_PRIMES[430]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[2], SHA512_PRIMES[431]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[3], SHA512_PRIMES[432]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[4], SHA512_PRIMES[433]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[5], SHA512_PRIMES[434]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[6], SHA512_PRIMES[435]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[7], SHA512_PRIMES[436]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[8], SHA512_PRIMES[437]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[9], SHA512_PRIMES[438]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[10], SHA512_PRIMES[439]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[11], SHA512_PRIMES[440]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[12], SHA512_PRIMES[441]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[13], SHA512_PRIMES[442]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[14], SHA512_PRIMES[443]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[15], SHA512_PRIMES[444]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W16, SHA512_PRIMES[445]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W17, SHA512_PRIMES[446]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W18, SHA512_PRIMES[447]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W19, SHA512_PRIMES[448]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W20, SHA512_PRIMES[449]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W21, SHA512_PRIMES[450]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W22, SHA512_PRIMES[451]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W23, SHA512_PRIMES[452]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W24, SHA512_PRIMES[453]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W25, SHA512_PRIMES[454]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W26, SHA512_PRIMES[455]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W27, SHA512_PRIMES[456]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W28, SHA512_PRIMES[457]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W29, SHA512_PRIMES[458]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W30, SHA512_PRIMES[459]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W31, SHA512_PRIMES[460]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W32, SHA512_PRIMES[461]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[0], SHA512_PRIMES[462]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[1], SHA512_PRIMES[463]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[2], SHA512_PRIMES[464]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[3], SHA512_PRIMES[465]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[4], SHA512_PRIMES[466]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[5], SHA512_PRIMES[467]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[6], SHA512_PRIMES[468]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[7], SHA512_PRIMES[469]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[8], SHA512_PRIMES[470]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[9], SHA512_PRIMES[471]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[10], SHA512_PRIMES[472]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[11], SHA512_PRIMES[473]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[12], SHA512_PRIMES[474]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[13], SHA512_PRIMES[475]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[14], SHA512_PRIMES[476]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[15], SHA512_PRIMES[477]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W16, SHA512_PRIMES[478]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W17, SHA512_PRIMES[479]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W18, SHA512_PRIMES[480]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W19, SHA512_PRIMES[481]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W20, SHA512_PRIMES[482]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W21, SHA512_PRIMES[483]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W22, SHA512_PRIMES[484]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W23, SHA512_PRIMES[485]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W24, SHA512_PRIMES[486]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W25, SHA512_PRIMES[487]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W26, SHA512_PRIMES[488]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W27, SHA512_PRIMES[489]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W28, SHA512_PRIMES[490]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W29, SHA512_PRIMES[491]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W30, SHA512_PRIMES[492]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W31, SHA512_PRIMES[493]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W32, SHA512_PRIMES[494]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[0], SHA512_PRIMES[495]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[1], SHA512_PRIMES[496]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[2], SHA512_PRIMES[497]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[3], SHA512_PRIMES[498]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[4], SHA512_PRIMES[499]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[5], SHA512_PRIMES[500]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[6], SHA512_PRIMES[501]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[7], SHA512_PRIMES[502]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[8], SHA512_PRIMES[503]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[9], SHA512_PRIMES[504]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[10], SHA512_PRIMES[505]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[11], SHA512_PRIMES[506]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[12], SHA512_PRIMES[507]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[13], SHA512_PRIMES[508]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[14], SHA512_PRIMES[509]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[15], SHA512_PRIMES[510]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W16, SHA512_PRIMES[511]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W17, SHA512_PRIMES[512]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W18, SHA512_PRIMES[513]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W19, SHA512_PRIMES[514]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W20, SHA512_PRIMES[515]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W21, SHA512_PRIMES[516]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W22, SHA512_PRIMES[517]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W23, SHA512_PRIMES[518]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W24, SHA512_PRIMES[519]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W25, SHA512_PRIMES[520]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W26, SHA512_PRIMES[521]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W27, SHA512_PRIMES[522]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W28, SHA512_PRIMES[523]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W29, SHA512_PRIMES[524]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W30, SHA512_PRIMES[525]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W31, SHA512_PRIMES[526]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W32, SHA512_PRIMES[527]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[0], SHA512_PRIMES[528]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[1], SHA512_PRIMES[529]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[2], SHA512_PRIMES[530]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[3], SHA512_PRIMES[531]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[4], SHA512_PRIMES[532]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[5], SHA512_PRIMES[533]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[6], SHA512_PRIMES[534]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[7], SHA512_PRIMES[535]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[8], SHA512_PRIMES[536]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[9], SHA512_PRIMES[537]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[10], SHA512_PRIMES[538]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[11], SHA512_PRIMES[539]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[12], SHA512_PRIMES[540]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[13], SHA512_PRIMES[541]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[14], SHA512_PRIMES[542]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[15], SHA512_PRIMES[543]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W16, SHA512_PRIMES[544]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W17, SHA512_PRIMES[545]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W18, SHA512_PRIMES[546]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W19, SHA512_PRIMES[547]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W20, SHA512_PRIMES[548]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W21, SHA512_PRIMES[549]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W22, SHA512_PRIMES[550]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W23, SHA512_PRIMES[551]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W24, SHA512_PRIMES[552]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, W25, SHA512_PRIMES[553]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, W26, SHA512_PRIMES[554]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, W27, SHA512_PRIMES[555]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, W28, SHA512_PRIMES[556]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, W29, SHA512_PRIMES[557]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, W30, SHA512_PRIMES[558]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, W31, SHA512_PRIMES[559]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, W32, SHA512_PRIMES[560]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[0], SHA512_PRIMES[561]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[1], SHA512_PRIMES[562]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[2], SHA512_PRIMES[563]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[3], SHA512_PRIMES[564]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[4], SHA512_PRIMES[565]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[5], SHA512_PRIMES[566]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[6], SHA512_PRIMES[567]);
    RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[7], SHA512_PRIMES[568]);
    RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[8], SHA512_PRIMES[569]);
    RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[9], SHA512_PRIMES[570]);
    RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[10], SHA512_PRIMES[571]);
    RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[11], SHA512_PRIMES[572]);
    RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[12], SHA512_PRIMES[573]);
    RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[13], SHA512_PRIMES[574]);
    RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[14], SHA512_PRIMES[575]);
    // ... (adicionar todas as 80 rounds)

    // Atualizar o hash final
    H[0] += A0;
    H[1] += A1;
    H[2] += A2;
    H[3] += A3;
    H[4] += A4;
    H[5] += A5;
    H[6] += A6;
    H[7] += A7;
}

// Implementação da função sha512_hash_two_blocks_message
void sha512_hash_two_blocks_message(ulong *message, ulong *H) {
    INIT_SHA512(H);
    sha512_procces(message, H);
    sha512_procces(message + 16, H);
}

// Implementação completa de pbkdf2_hmac_sha512_long
void pbkdf2_hmac_sha512_long(ulong *inner_data, ulong *outer_data, ulong *T) {
    ulong U[8], OU[8], GU[8];
    INIT_SHA512(GU);
    INIT_SHA512(OU);

    sha512_procces(inner_data, GU);
    sha512_procces(outer_data, OU);
    COPY_EIGHT(U, GU);
    sha512_procces(inner_data+16, U);
    COPY_EIGHT(outer_data + 16, U);
    COPY_EIGHT(T, OU);
    sha512_procces(outer_data+16, T);
    COPY_EIGHT(U, T);
    inner_data[24] = 0x8000000000000000UL;
    inner_data[31] = 1536UL;
    COPY_EIGHT(outer_data + 16, T);  
    
    for (ushort i = 1; i < 2048; ++i) {
        COPY_EIGHT(inner_data + 16, U);
        COPY_EIGHT(U, GU);
        sha512_procces(inner_data + 16, U);
        COPY_EIGHT(outer_data + 16, U);
        COPY_EIGHT(U, OU);
        sha512_procces(outer_data + 16, U);
        COPY_EIGHT_XOR(T, U);
    }
}

// Definições globais para os kernels OpenCL
#ifndef MAIN_CL
#define MAIN_CL

// Definições de tipos
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

// Constantes
#define WORD_LIST_SIZE 34
#define TARGET_ADDRESS "1EciYvS7FFjSYfrWxsWYjGB8K9BobBfCXw"

// Estruturas de dados
typedef struct {
    uint64_t high;
    uint64_t low;
} uint128_t;

// Macros para processamento de seed
#define prepareSeedString(seedNum, seedString, offset)                         \
  {                                                                            \
    for (int i = 0, y; i < 12; i++) {                                          \
      y = seedNum[i];                                                          \
      for (int j = 0; j < 9; j++) {                                            \
        seedString[offset + j] = wordsString[y][j];                            \
      }                                                                        \
      offset += wordsLen[y] + 1;                                               \
    }                                                                          \
    seedString[offset - 1] = '\0';                                             \
  }

#define ucharLong(input, input_len, output, offset)                            \
  {                                                                            \
    const uchar num_ulongs = (input_len + 7) / 8;                              \
    for (uchar i = offset; i < num_ulongs; i++) {                              \
      const uchar baseIndex = i * 8;                                           \
      output[i] = ((ulong)input[baseIndex] << 56UL) |                          \
                  ((ulong)input[baseIndex + 1] << 48UL) |                      \
                  ((ulong)input[baseIndex + 2] << 40UL) |                      \
                  ((ulong)input[baseIndex + 3] << 32UL) |                      \
                  ((ulong)input[baseIndex + 4] << 24UL) |                      \
                  ((ulong)input[baseIndex + 5] << 16UL) |                      \
                  ((ulong)input[baseIndex + 6] << 8UL) |                       \
                  ((ulong)input[baseIndex + 7]);                               \
    }                                                                          \
    for (uchar i = num_ulongs; i < 16; i++) {                                  \
      output[i] = 0;                                                           \
    }                                                                          \
  }

#define prepareSeedNumber(seedNum, memHigh, memLow)                            \
  seedNum[0] = (memHigh & (2047UL << 53UL)) >> 53UL;                           \
  seedNum[1] = (memHigh & (2047UL << 42UL)) >> 42UL;                           \
  seedNum[2] = (memHigh & (2047UL << 31UL)) >> 31UL;                           \
  seedNum[3] = (memHigh & (2047UL << 20UL)) >> 20UL;                           \
  seedNum[4] = (memHigh & (2047UL << 9UL)) >> 9UL;                             \
  seedNum[5] = (memHigh << 55UL) >> 53UL | ((memLow & (3UL << 62UL)) >> 62UL); \
  seedNum[6] = (memLow & (2047UL << 51UL)) >> 51UL;                            \
  seedNum[7] = (memLow & (2047UL << 40UL)) >> 40UL;                            \
  seedNum[8] = (memLow & (2047UL << 29UL)) >> 29UL;                            \
  seedNum[9] = (memLow & (2047UL << 18UL)) >> 18UL;                            \
  seedNum[10] = (memLow & (2047UL << 7UL)) >> 7UL;                             \
  seedNum[11] = (memLow << 57UL) >> 53UL | sha256_from_byte(memHigh, memLow) >> 4UL;

// Dados constantes em memória constante
__constant ulong gInnerData[32] = {
    0x3636363636363636UL, 0x3636363636363636UL,
    0x3636363636363636UL, 0x3636363636363636UL,
    0x3636363636363636UL, 0x3636363636363636UL,
    0x3636363636363636UL, 0x3636363636363636UL,
    0x3636363636363636UL, 0x3636363636363636UL,
    0x3636363636363636UL, 0x3636363636363636UL,
    0x3636363636363636UL, 0x3636363636363636UL,
    0x3636363636363636UL, 0x3636363636363636UL,
    7885351518267664739UL, 6442450944UL,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1120UL
};

__constant ulong gOuterData[32] = {
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x5C5C5C5C5C5C5C5CUL, 0x5C5C5C5C5C5C5C5CUL,
    0x8000000000000000UL, 0, 0, 0, 0, 0, 0, 1536U
};

// String constante em memória constante
__constant uchar zeroString[128] = {0};

// Palavras e comprimentos em memória constante
__constant char wordsString[WORD_LIST_SIZE][16] = {
    "artigo\0\0\0\0\0\0\0\0\0",    // 6
    "ativo\0\0\0\0\0\0\0\0\0\0",    // 5
    "busca\0\0\0\0\0\0\0\0\0\0",    // 5
    "baseado\0\0\0\0\0\0\0\0",      // 7
    "cadeado\0\0\0\0\0\0\0\0",      // 7
    "camada\0\0\0\0\0\0\0\0\0",     // 6
    "chave\0\0\0\0\0\0\0\0\0\0",    // 5
    "clareza\0\0\0\0\0\0\0\0",      // 7
    "clone\0\0\0\0\0\0\0\0\0\0",    // 5
    "criminal\0\0\0\0\0\0\0",       // 8
    "desafio\0\0\0\0\0\0\0\0",      // 7
    "devido\0\0\0\0\0\0\0\0\0",     // 6
    "dinheiro\0\0\0\0\0\0\0",       // 8
    "enquanto\0\0\0\0\0\0\0",       // 8
    "entanto\0\0\0\0\0\0\0\0",      // 7
    "global\0\0\0\0\0\0\0\0\0",     // 6
    "inocente\0\0\0\0\0\0\0",       // 8
    "mais\0\0\0\0\0\0\0\0\0\0\0",   // 4
    "manter\0\0\0\0\0\0\0\0\0",     // 6
    "mestre\0\0\0\0\0\0\0\0\0",     // 6
    "moeda\0\0\0\0\0\0\0\0\0\0",    // 5
    "negativa\0\0\0\0\0\0\0",       // 8
    "nordeste\0\0\0\0\0\0\0",       // 8
    "perfeito\0\0\0\0\0\0\0",       // 8
    "pessoa\0\0\0\0\0\0\0\0\0",     // 6
    "quase\0\0\0\0\0\0\0\0\0\0",    // 5
    "sonegar\0\0\0\0\0\0\0\0",      // 7
    "tabela\0\0\0\0\0\0\0\0\0",     // 6
    "tarefa\0\0\0\0\0\0\0\0\0",     // 6
    "treino\0\0\0\0\0\0\0\0\0",     // 6
    "uniforme\0\0\0\0\0\0\0",       // 8
    "verdade\0\0\0\0\0\0\0\0",      // 7
    "visto\0\0\0\0\0\0\0\0\0\0",    // 5
    "zangado\0\0\0\0\0\0\0\0"       // 7
};

__constant int wordsLen[WORD_LIST_SIZE] = {
    6,  // artigo
    5,  // ativo
    5,  // busca
    7,  // baseado
    7,  // cadeado
    6,  // camada
    5,  // chave
    7,  // clareza
    5,  // clone
    8,  // criminal
    7,  // desafio
    6,  // devido
    8,  // dinheiro
    8,  // enquanto
    7,  // entanto
    6,  // global
    8,  // inocente
    4,  // mais
    6,  // manter
    6,  // mestre
    5,  // moeda
    8,  // negativa
    8,  // nordeste
    8,  // perfeito
    6,  // pessoa
    5,  // quase
    7,  // sonegar
    6,  // tabela
    6,  // tarefa
    6,  // treino
    8,  // uniforme
    7,  // verdade
    5,  // visto
    7   // zangado
};

// Kernel principal
__kernel void search_mnemonic(
    __global const ulong* L,        // Input: valor inicial low
    __global const ulong* H,        // Input: valor high
    __global ulong* output,         // Output: resultados
    __global uint* valid_flags      // Output: flags de validação
) {
    int gid = get_global_id(0);
    int lid = get_local_id(0);
    
    // Obter valores de entrada
    ulong memHigh = H[0];
    ulong firstMem = L[0];
    ulong memLow = firstMem + gid;

    // Arrays locais
    ulong inner_data[32];
    ulong outer_data[32];
    ulong mnemonicLong[16];
    ulong pbkdLong[16];
    uint seedNum[16];
    uchar mnemonicString[128] = {0};

    // Inicializar offset
    uint offset = 0;
    
    // Preparar seed
    prepareSeedNumber(seedNum, memHigh, memLow);
    prepareSeedString(seedNum, mnemonicString, offset);
    ucharLong(mnemonicString, offset - 1, mnemonicLong, 0);

    // Preparar dados HMAC
    for (lid = 0; lid < 16; lid++) {
        pbkdLong[lid] = 0;
        inner_data[lid] = mnemonicLong[lid] ^ 0x3636363636363636UL;
        outer_data[lid] = mnemonicLong[lid] ^ 0x5C5C5C5C5C5C5C5CUL;
        outer_data[lid + 16] = gOuterData[lid + 16];
        inner_data[lid + 16] = gInnerData[lid + 16];
    }

    // Gerar seed
    pbkdf2_hmac_sha512_long(inner_data, outer_data, pbkdLong);

    // Debug output a cada 50000 iterações
    if (gid % 50000 == 0) {
        printf("Group: %d | Seed: \"%s\" | %016lx\n", gid, mnemonicString,
               pbkdLong[0]);
    }

    // Calcular índice de saída
    ulong index = memLow - firstMem;
    
    // Armazenar resultados
    output[index] = pbkdLong[0];
    valid_flags[index] = 1;  // Marcar como processado
}

__kernel void pbkdf2_hmac_sha512_test(__global uchar *py,
                                      __global uchar *input) {
  /*
    ulong mnemonic_long[32];

    ulong aa[8];
    uchar result[128];
    uchar_to_ulong(input, strlen(input), mnemonic_long, 0);
    pbkdf2_hmac_sha512_long(mnemonic_long, strlen(input), aa);
    ulong_array_to_char(aa, 8, result);

    if (strcmp(result, py)) {
      printf("\nIguais");
    } else {
      printf("\nDiferentes: ");
      printf("Veio de la: %s %s %s", input, result, py);
    }*/
}

#endif // MAIN_CL
