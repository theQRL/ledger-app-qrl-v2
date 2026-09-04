#include "keccakf.h"

// Rotate left 64-bit.
// r[0] is 0, so the shift count must be masked: evaluating x >> 64 directly is
// undefined behaviour (UBSan: "shift exponent 64 is too large"). Masking keeps
// this branchless, which matters in a primitive on the signing path.
static inline uint64_t rol64(uint64_t x, unsigned n) {
    return (x << n) | (x >> ((64u - n) & 63u));
}

// Keccak-f[1600], 24 rounds
void keccakf(uint64_t s[25]) {
    const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
        0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
        0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
    const int r[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55, 20, 3,  10, 43,
                       25, 39, 41, 45, 15, 21, 8,  18, 2,  61, 56, 14};
    for (int round = 0; round < 24; round++) {
        uint64_t C[5], D[5], B[25];
        for (int x = 0; x < 5; x++) C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        for (int x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rol64(C[(x + 1) % 5], 1);
        for (int i = 0; i < 25; i++) s[i] ^= D[i % 5];
        for (int i = 0; i < 25; i++) {
            int x = i % 5, y = i / 5;
            B[y + 5 * ((2 * x + 3 * y) % 5)] = rol64(s[i], r[i]);
        }
        for (int i = 0; i < 25; i++)
            s[i] = B[i] ^ ((~B[(i + 1) % 5 + 5 * (i / 5)]) & B[(i + 2) % 5 + 5 * (i / 5)]);
        s[0] ^= RC[round];
    }
}
