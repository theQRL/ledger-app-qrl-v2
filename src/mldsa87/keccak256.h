#include <stdint.h>

// Replace with Ledger OS secure memset, e.g. os_memset
#define MEMSET memset

// keccak256 context
typedef struct {
    uint64_t s[25];
    size_t pos;
    int squeezing;
} keccak256_ctx;

#define keccak256_RATE 136

void keccak256_init(keccak256_ctx *ctx);
void keccak256_absorb(keccak256_ctx *ctx, const uint8_t *in, size_t inlen);
void keccak256_finalize(keccak256_ctx *ctx);
void keccak256_squeeze(keccak256_ctx *ctx, uint8_t *out);
void keccak256_clear(keccak256_ctx *ctx);
