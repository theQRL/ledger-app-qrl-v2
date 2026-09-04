#include <stdint.h>
#include "shake128.h"
#include <stdlib.h>
#include <string.h>
#include "keccakf.h"


void shake128_init(shake128_ctx *ctx) {
    MEMSET(ctx, 0, sizeof(*ctx));
}

void shake128_absorb(shake128_ctx *ctx, const uint8_t *in, size_t inlen) {
    while (inlen--) {
        size_t i = ctx->pos++;
        ctx->s[i / 8] ^= (uint64_t) (*in++) << (8 * (i % 8));
        if (ctx->pos == 168) {
            keccakf(ctx->s);
            ctx->pos = 0;
        }
    }
}

void shake128_finalize(shake128_ctx *ctx) {
    ctx->s[ctx->pos / 8] ^= (uint64_t) 0x1F << (8 * (ctx->pos % 8));
    ctx->s[(168 - 1) / 8] ^= (uint64_t) 0x80 << (8 * ((168 - 1) % 8));
    keccakf(ctx->s);
    ctx->pos = 0;
    ctx->squeezing = 1;
}

void shake128_squeeze(shake128_ctx *ctx, uint8_t *out, size_t outlen) {
    if (!ctx->squeezing) shake128_finalize(ctx);
    while (outlen--) {
        *out++ = (ctx->s[ctx->pos / 8] >> (8 * (ctx->pos % 8))) & 0xFF;
        if (++ctx->pos == 168) {
            keccakf(ctx->s);
            ctx->pos = 0;
        }
    }
}

void shake128_clear(shake128_ctx *ctx) {
    MEMSET(ctx, 0, sizeof(*ctx));
}
