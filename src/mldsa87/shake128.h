#include <stdint.h>
#include <stdlib.h>

// Replace with Ledger OS secure memset, e.g. os_memset
#define MEMSET memset

// SHAKE128 context
typedef struct {
    uint64_t s[25];
    size_t pos;
    int squeezing;
} shake128_ctx;

void shake128_init(shake128_ctx *ctx);
void shake128_absorb(shake128_ctx *ctx, const uint8_t *in, size_t inlen);
void shake128_finalize(shake128_ctx *ctx);
void shake128_squeeze(shake128_ctx *ctx, uint8_t *out, size_t outlen);
void shake128_clear(shake128_ctx *ctx);
