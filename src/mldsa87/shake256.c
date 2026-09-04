#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cx.h"
#include "keccakf.h"

// Replace with Ledger OS secure memset, e.g. os_memset
#define MEMSET memset


// SHAKE256 context
typedef struct {
    uint64_t s[25];
    size_t pos;
    int squeezing;
} shake256_ctx;

#define SHAKE256_RATE 136

void shake256_init(shake256_ctx *ctx) {
    MEMSET(ctx, 0, sizeof(*ctx));
}

void shake256_absorb(shake256_ctx *ctx, const uint8_t *in, size_t inlen) {
    while (inlen--) {
        size_t i = ctx->pos++;
        ctx->s[i / 8] ^= (uint64_t) (*in++) << (8 * (i % 8));
        if (ctx->pos == SHAKE256_RATE) {
            keccakf(ctx->s);
            ctx->pos = 0;
        }
    }
}

void shake256_finalize(shake256_ctx *ctx) {
    ctx->s[ctx->pos / 8] ^= (uint64_t) 0x1F << (8 * (ctx->pos % 8));
    ctx->s[(SHAKE256_RATE - 1) / 8] ^= (uint64_t) 0x80 << (8 * ((SHAKE256_RATE - 1) % 8));
    keccakf(ctx->s);
    ctx->pos = 0;
    ctx->squeezing = 1;
}

void shake256_squeeze(shake256_ctx *ctx, uint8_t *out, size_t outlen) {
    if (!ctx->squeezing) shake256_finalize(ctx);
    while (outlen--) {
        *out++ = (ctx->s[ctx->pos / 8] >> (8 * (ctx->pos % 8))) & 0xFF;
        if (++ctx->pos == SHAKE256_RATE) {
            keccakf(ctx->s);
            ctx->pos = 0;
        }
    }
}

void shake256_clear(shake256_ctx *ctx) {
    MEMSET(ctx, 0, sizeof(*ctx));
}
