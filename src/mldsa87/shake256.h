#include <stdint.h>

// Replace with Ledger OS secure memset, e.g. os_memset
#define MEMSET memset

// SHAKE256 context
typedef struct {
    uint64_t s[25];
    size_t pos;
    int squeezing;
} shake256_ctx;

#define SHAKE256_RATE 136

void shake256_init(shake256_ctx *ctx);
void shake256_absorb(shake256_ctx *ctx, const uint8_t *in, size_t inlen);
void shake256_finalize(shake256_ctx *ctx);
void shake256_squeeze(shake256_ctx *ctx, uint8_t *out, size_t outlen);
void shake256_clear(shake256_ctx *ctx);
