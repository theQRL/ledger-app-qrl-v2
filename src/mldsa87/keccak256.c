#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cx.h"
#include "keccakf.h"

// Replace with Ledger OS secure memset, e.g. os_memset
#define MEMSET memset


// KECCAK256 context
typedef struct {
    uint64_t s[25];
    size_t pos;
    int squeezing;
} keccak256_ctx;

#define KECCAK256_RATE 136

void keccak256_init(keccak256_ctx *ctx) {
    MEMSET(ctx, 0, sizeof(*ctx));
}

void keccak256_absorb(keccak256_ctx *ctx, const uint8_t *in, size_t inlen) {
    while (inlen--) {
        size_t i = ctx->pos++;
        ctx->s[i / 8] ^= (uint64_t) (*in++) << (8 * (i % 8));
        if (ctx->pos == KECCAK256_RATE) {
            keccakf(ctx->s);
            ctx->pos = 0;
        }
    }
}

void keccak256_finalize(keccak256_ctx *ctx) {
    ctx->s[ctx->pos / 8] ^= (uint64_t) 0x01 << (8 * (ctx->pos % 8));
    ctx->s[(KECCAK256_RATE - 1) / 8] ^= (uint64_t) 0x80 << (8 * ((KECCAK256_RATE - 1) % 8));
    keccakf(ctx->s);
    ctx->pos = 0;
    ctx->squeezing = 1;
}

void keccak256_squeeze(keccak256_ctx *ctx, uint8_t *out) {
    if (!ctx->squeezing) keccak256_finalize(ctx);
    uint8_t outlen = 32;
    while (outlen--) {
        *out++ = (ctx->s[ctx->pos / 8] >> (8 * (ctx->pos % 8))) & 0xFF;
        if (++ctx->pos == KECCAK256_RATE) {
            keccakf(ctx->s);
            ctx->pos = 0;
        }
    }
}

void keccak256_clear(keccak256_ctx *ctx) {
    MEMSET(ctx, 0, sizeof(*ctx));
}
