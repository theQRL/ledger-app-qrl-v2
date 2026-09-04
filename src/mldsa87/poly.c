#include "poly.h"
#include "reduce.h"
#include "ntt.h"
#include "rounding.h"
#include <string.h>
#include "shake128.h"
#include "shake256.h"
#include "error.h"
#include "cx.h"

void poly_c_addq(Poly *a) {
    for (int i = 0; i < N; i++) {
        a->coeffs[i] = c_addq(a->coeffs[i]);
    }
}

void poly_reduce(Poly *a) {
    for (int i = 0; i < N; i++) {
        a->coeffs[i] = reduce_32(a->coeffs[i]);
    }
}

void poly_add(Poly *c, Poly *a, Poly *b) {
    for (int i = 0; i < N; i++) {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

void poly_sub(Poly *c, Poly *a, Poly *b) {
    for (int i = 0; i < N; i++) {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

void poly_shitf_l(Poly *a) {
    for (int i = 0; i < N; i++) {
        a->coeffs[i] <<= D;
    }
}

void poly_ntt(Poly *a) {
    ntt(&a->coeffs);
}

void poly_inv_ntt_to_mont(Poly *a) {
    inv_ntt_to_mont(&a->coeffs);
}

void poly_pointwise_montgomery(Poly *c, Poly *a, Poly *b) {
    for (int i = 0; i < N; i++) {
        c->coeffs[i] = montgomery_reduce((int64_t) (a->coeffs[i]) * (int64_t) (b->coeffs[i]));
    }
}

void poly_power2_round(Poly *a1, Poly *a0, Poly *a) {
    for (int i = 0; i < N; i++) {
        a1->coeffs[i] = power2_round(&a0->coeffs[i], a->coeffs[i]);
    }
}

void poly_decompose(Poly *a1, Poly *a0, Poly *a) {
    for (int i = 0; i < N; i++) {
        a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);
    }
}

uint32_t poly_make_hint(Poly *h, Poly *a0, Poly *a1) {
    uint32_t s = 0;
    for (int i = 0; i < N; i++) {
        h->coeffs[i] = (int32_t) (make_hint(a0->coeffs[i], a1->coeffs[i]));
        s += (uint32_t) (h->coeffs[i]);
    }

    return s;
}

void poly_use_hint(Poly *b, Poly *a, Poly *h) {
    for (int i = 0; i < N; i++) {
        b->coeffs[i] = use_hint(a->coeffs[i], (int32_t) (h->coeffs[i]));
    }
}

int32_t poly_chk_norm(Poly *a, int32_t B) {
    int32_t t = 0;
    uint32_t violation = 0;

    if (B > ((Q_CONST - 1) / 8)) {
        return 1;
    }

    /* It is ok to leak which coefficient violates the bound since
       the probability for each coefficient is independent of secret
       data but we must not leak the sign of the centralized representative. */
    for (int i = 0; i < N; i++) {
        /* Absolute value of centralized representative */
        t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

        violation |= 1U ^ ((uint32_t) (t - B) >> 31);
    }

    return (int32_t) (violation & 1U);
}

ErrorCode poly_uniform(Poly *a, uint8_t (*seed)[SEED_BYTES], uint16_t nonce) {
    size_t bufLen = POLY_UNIFORM_N_BLOCKS * STREAM_128_BLOCK_BYTES;
    uint8_t buf[POLY_UNIFORM_N_BLOCKS * STREAM_128_BLOCK_BYTES + 2] = {0};

    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, *seed, SEED_BYTES);
    uint8_t nonces[2] = {(uint8_t) (nonce), (uint8_t) (nonce >> 8)};
    shake128_absorb(&ctx, nonces, 2);
    shake128_finalize(&ctx);
    shake128_squeeze(&ctx, buf, POLY_UNIFORM_N_BLOCKS * STREAM_128_BLOCK_BYTES + 2);
    uint32_t ctr = rej_uniform(a->coeffs, N, buf, POLY_UNIFORM_N_BLOCKS * STREAM_128_BLOCK_BYTES);
    uint8_t *ptr = buf;

    while (ctr < N) {
        size_t off = bufLen % 3;
        for (size_t i = 0; i < off; i++) {
            buf[i] = buf[bufLen - off + i];
        }

        ptr = ptr + off;
        shake128_squeeze(&ctx, ptr, STREAM_128_BLOCK_BYTES);
        bufLen = STREAM_128_BLOCK_BYTES + off;
        ctr += rej_uniform(a->coeffs, N - ctr, buf, bufLen);
    }
    shake128_clear(&ctx);
    return 0;
}

uint32_t rej_uniform(int32_t a[], size_t a_len, uint8_t buf[], size_t buf_len) {
    uint32_t ctr = 0, pos = 0, t = 0;
    uint32_t aLen = (uint32_t) (a_len);
    uint32_t bufLen = (uint32_t) (buf_len);
    while (ctr < aLen && pos + 3 <= bufLen) {
        t = (uint32_t) (buf[pos]);
        t |= (uint32_t) (buf[pos + 1]) << 8;
        t |= (uint32_t) (buf[pos + 2]) << 16;
        t &= 0x7fffff;

        pos += 3;

        if (t < Q_CONST) {
            a[ctr] = (int32_t) t;
            ctr++;
        }
    }
    return ctr;
}

uint32_t rej_eta(int32_t a[], size_t a_len, uint8_t buf[], size_t buf_len) {
    uint32_t ctr = 0, pos = 0, t0 = 0, t1 = 0;
    uint32_t bufLen = (uint32_t) buf_len, aLen = (uint32_t) a_len;
    while (ctr < aLen && pos < bufLen) {
        t0 = (uint32_t) (buf[pos] & 0x0F);
        t1 = (uint32_t) (buf[pos] >> 4);
        pos++;

        if (t0 < 15) {
            t0 = t0 - (205 * t0 >> 10) * 5;
            a[ctr] = (int32_t) (2 - t0);
            ctr++;
        }
        if (t1 < 15 && ctr < aLen) {
            t1 = t1 - (205 * t1 >> 10) * 5;
            a[ctr] = (int32_t) (2 - t1);
            ctr++;
        }
    }
    return ctr;
}

ErrorCode poly_uniform_eta(Poly *a, uint8_t (*seed)[CRH_BYTES], uint16_t nonce) {
    uint8_t buf[POLY_UNIFORM_ETA_N_BLOCKS * STREAM_256_BLOCK_BYTES] = {0};
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, *seed, CRH_BYTES);
    uint8_t nonces[2] = {(uint8_t) (nonce), (uint8_t) (nonce >> 8)};
    shake256_absorb(&ctx, nonces, 2);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, buf, POLY_UNIFORM_ETA_N_BLOCKS * STREAM_256_BLOCK_BYTES);

    uint32_t ctr = rej_eta(a->coeffs, N, buf, POLY_UNIFORM_ETA_N_BLOCKS * STREAM_256_BLOCK_BYTES);
    while (ctr < N) {
        shake256_squeeze(&ctx, buf, STREAM_256_BLOCK_BYTES);
        ctr += rej_eta(a->coeffs + ctr, N - ctr, buf, STREAM_256_BLOCK_BYTES);
    }
    shake256_clear(&ctx);
    return 0;
}

void poly_uniform_gamma1(Poly *a, uint8_t seed[CRH_BYTES], uint16_t nonce) {
    uint8_t buf[POLY_UNIFORM_GAMMA1_N_BLOCKS * STREAM_256_BLOCK_BYTES] = {0};
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, seed, CRH_BYTES);
    uint8_t nonces[2] = {(uint8_t) nonce, (uint8_t) (nonce >> 8)};
    shake256_absorb(&ctx, nonces, 2);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, buf, POLY_UNIFORM_GAMMA1_N_BLOCKS * STREAM_256_BLOCK_BYTES);
    poly_z_unpack(a, buf);
}

ErrorCode poly_challenge(Poly *c, uint8_t seed[], size_t seed_len) {
    uint32_t pos = 0, b = 0;
    if (seed_len != CTILDE_BYTES) {
        return ERR_INVALID_SEED_LENGTH;
    }
    uint8_t buf[SHAKE256_RATE];
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, seed, seed_len);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, buf, SHAKE256_RATE);

    uint64_t signs = 0;
    for (uint64_t i = 0; i < 8; i++) {
        signs |= (uint64_t) buf[i] << (8 * i);
    }
    pos = 8;

    for (int i = 0; i < N; i++) {
        c->coeffs[i] = 0;
    }
    for (int i = N - TAU; i < N; i++) {
        while (1) {
            if (pos >= SHAKE256_RATE) {
                shake256_squeeze(&ctx, buf, SHAKE256_RATE);
                pos = 0;
            }

            b = (uint32_t) buf[pos];
            pos++;
            if (!(b > (uint32_t) i)) {
                break;
            }
        }

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = (int32_t) (1 - 2 * (signs & 1));
        signs >>= 1;
    }
    shake256_clear(&ctx);
    return 0;
}

void poly_eta_pack(uint8_t r[], Poly *a) {
    uint8_t t[8] = {0};

    for (int i = 0; i < N / 8; i++) {
        t[0] = (uint8_t) (ETA - a->coeffs[8 * i + 0]);
        t[1] = (uint8_t) (ETA - a->coeffs[8 * i + 1]);
        t[2] = (uint8_t) (ETA - a->coeffs[8 * i + 2]);
        t[3] = (uint8_t) (ETA - a->coeffs[8 * i + 3]);
        t[4] = (uint8_t) (ETA - a->coeffs[8 * i + 4]);
        t[5] = (uint8_t) (ETA - a->coeffs[8 * i + 5]);
        t[6] = (uint8_t) (ETA - a->coeffs[8 * i + 6]);
        t[7] = (uint8_t) (ETA - a->coeffs[8 * i + 7]);

        r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
        r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
}

void poly_eta_unpack(Poly *r, uint8_t a[]) {
    for (int i = 0; i < N / 8; i++) {
        r->coeffs[8 * i + 0] = (int32_t) ((a[3 * i + 0] >> 0) & 7);
        r->coeffs[8 * i + 1] = (int32_t) ((a[3 * i + 0] >> 3) & 7);
        r->coeffs[8 * i + 2] = (int32_t) (((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7);
        r->coeffs[8 * i + 3] = (int32_t) ((a[3 * i + 1] >> 1) & 7);
        r->coeffs[8 * i + 4] = (int32_t) ((a[3 * i + 1] >> 4) & 7);
        r->coeffs[8 * i + 5] = (int32_t) (((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7);
        r->coeffs[8 * i + 6] = (int32_t) ((a[3 * i + 2] >> 2) & 7);
        r->coeffs[8 * i + 7] = (int32_t) ((a[3 * i + 2] >> 5) & 7);
        r->coeffs[8 * i + 0] = ETA - r->coeffs[8 * i + 0];
        r->coeffs[8 * i + 1] = ETA - r->coeffs[8 * i + 1];
        r->coeffs[8 * i + 2] = ETA - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = ETA - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = ETA - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = ETA - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = ETA - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = ETA - r->coeffs[8 * i + 7];
    }
}

void poly_t1_pack(uint8_t r[], Poly *a) {
    for (int i = 0; i < N / 4; i++) {
        r[5 * i + 0] = (uint8_t) (a->coeffs[4 * i + 0] >> 0);
        r[5 * i + 1] = (uint8_t) ((a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2));
        r[5 * i + 2] = (uint8_t) ((a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4));
        r[5 * i + 3] = (uint8_t) ((a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6));
        r[5 * i + 4] = (uint8_t) (a->coeffs[4 * i + 3] >> 2);
    }
}

void poly_t1_unpack(Poly *r, uint8_t a[]) {
    for (int i = 0; i < N / 4; i++) {
        r->coeffs[4 * i + 0] =
            (int32_t) (((uint32_t) (a[5 * i + 0] >> 0) | ((uint32_t) (a[5 * i + 1]) << 8)) & 0x3FF);
        r->coeffs[4 * i + 1] =
            (int32_t) (((uint32_t) (a[5 * i + 1] >> 2) | ((uint32_t) (a[5 * i + 2]) << 6)) & 0x3FF);
        r->coeffs[4 * i + 2] =
            (int32_t) (((uint32_t) (a[5 * i + 2] >> 4) | ((uint32_t) (a[5 * i + 3]) << 4)) & 0x3FF);
        r->coeffs[4 * i + 3] =
            (int32_t) (((uint32_t) (a[5 * i + 3] >> 6) | ((uint32_t) (a[5 * i + 4]) << 2)) & 0x3FF);
    }
}

void poly_t0_pack(uint8_t r[], Poly *a) {
    uint32_t t[8] = {0};

    for (int i = 0; i < N / 8; i++) {
        t[0] = (uint32_t) ((1 << (D - 1)) - a->coeffs[8 * i + 0]);
        t[1] = (uint32_t) ((1 << (D - 1)) - a->coeffs[8 * i + 1]);
        t[2] = (uint32_t) ((1 << (D - 1)) - a->coeffs[8 * i + 2]);
        t[3] = (uint32_t) ((1 << (D - 1)) - a->coeffs[8 * i + 3]);
        t[4] = (uint32_t) ((1 << (D - 1)) - a->coeffs[8 * i + 4]);
        t[5] = (uint32_t) ((1 << (D - 1)) - a->coeffs[8 * i + 5]);
        t[6] = (uint32_t) ((1 << (D - 1)) - a->coeffs[8 * i + 6]);
        t[7] = (uint32_t) ((1 << (D - 1)) - a->coeffs[8 * i + 7]);

        r[13 * i + 0] = (uint8_t) (t[0]);
        r[13 * i + 1] = (uint8_t) (t[0] >> 8);
        r[13 * i + 1] |= (uint8_t) (t[1] << 5);
        r[13 * i + 2] = (uint8_t) (t[1] >> 3);
        r[13 * i + 3] = (uint8_t) (t[1] >> 11);
        r[13 * i + 3] |= (uint8_t) (t[2] << 2);
        r[13 * i + 4] = (uint8_t) (t[2] >> 6);
        r[13 * i + 4] |= (uint8_t) (t[3] << 7);
        r[13 * i + 5] = (uint8_t) (t[3] >> 1);
        r[13 * i + 6] = (uint8_t) (t[3] >> 9);
        r[13 * i + 6] |= (uint8_t) (t[4] << 4);
        r[13 * i + 7] = (uint8_t) (t[4] >> 4);
        r[13 * i + 8] = (uint8_t) (t[4] >> 12);
        r[13 * i + 8] |= (uint8_t) (t[5] << 1);
        r[13 * i + 9] = (uint8_t) (t[5] >> 7);
        r[13 * i + 9] |= (uint8_t) (t[6] << 6);
        r[13 * i + 10] = (uint8_t) (t[6] >> 2);
        r[13 * i + 11] = (uint8_t) (t[6] >> 10);
        r[13 * i + 11] |= (uint8_t) (t[7] << 3);
        r[13 * i + 12] = (uint8_t) (t[7] >> 5);
    }
}

void poly_t0_unpack(Poly *r, uint8_t a[]) {
    for (int i = 0; i < N / 8; i++) {
        r->coeffs[8 * i + 0] = (int32_t) (a[13 * i + 0]);
        r->coeffs[8 * i + 0] |= (int32_t) ((uint32_t) (a[13 * i + 1]) << 8);
        r->coeffs[8 * i + 0] &= 0x1FFF;

        r->coeffs[8 * i + 1] = (int32_t) (a[13 * i + 1] >> 5);
        r->coeffs[8 * i + 1] |= (int32_t) ((uint32_t) (a[13 * i + 2]) << 3);
        r->coeffs[8 * i + 1] |= (int32_t) ((uint32_t) (a[13 * i + 3]) << 11);
        r->coeffs[8 * i + 1] &= 0x1FFF;

        r->coeffs[8 * i + 2] = (int32_t) (a[13 * i + 3] >> 2);
        r->coeffs[8 * i + 2] |= (int32_t) ((uint32_t) (a[13 * i + 4]) << 6);
        r->coeffs[8 * i + 2] &= 0x1FFF;

        r->coeffs[8 * i + 3] = (int32_t) (a[13 * i + 4] >> 7);
        r->coeffs[8 * i + 3] |= (int32_t) ((uint32_t) (a[13 * i + 5]) << 1);
        r->coeffs[8 * i + 3] |= (int32_t) ((uint32_t) (a[13 * i + 6]) << 9);
        r->coeffs[8 * i + 3] &= 0x1FFF;

        r->coeffs[8 * i + 4] = (int32_t) (a[13 * i + 6] >> 4);
        r->coeffs[8 * i + 4] |= (int32_t) ((uint32_t) (a[13 * i + 7]) << 4);
        r->coeffs[8 * i + 4] |= (int32_t) ((uint32_t) (a[13 * i + 8]) << 12);
        r->coeffs[8 * i + 4] &= 0x1FFF;

        r->coeffs[8 * i + 5] = (int32_t) (a[13 * i + 8] >> 1);
        r->coeffs[8 * i + 5] |= (int32_t) ((uint32_t) (a[13 * i + 9]) << 7);
        r->coeffs[8 * i + 5] &= 0x1FFF;

        r->coeffs[8 * i + 6] = (int32_t) (a[13 * i + 9] >> 6);
        r->coeffs[8 * i + 6] |= (int32_t) ((uint32_t) (a[13 * i + 10]) << 2);
        r->coeffs[8 * i + 6] |= (int32_t) ((uint32_t) (a[13 * i + 11]) << 10);
        r->coeffs[8 * i + 6] &= 0x1FFF;

        r->coeffs[8 * i + 7] = (int32_t) (a[13 * i + 11] >> 3);
        r->coeffs[8 * i + 7] |= (int32_t) ((uint32_t) (a[13 * i + 12]) << 5);
        r->coeffs[8 * i + 7] &= 0x1FFF;

        r->coeffs[8 * i + 0] = (1 << (D - 1)) - r->coeffs[8 * i + 0];
        r->coeffs[8 * i + 1] = (1 << (D - 1)) - r->coeffs[8 * i + 1];
        r->coeffs[8 * i + 2] = (1 << (D - 1)) - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = (1 << (D - 1)) - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = (1 << (D - 1)) - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = (1 << (D - 1)) - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = (1 << (D - 1)) - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = (1 << (D - 1)) - r->coeffs[8 * i + 7];
    }
}

void poly_z_pack(uint8_t r[], Poly *a) {
    uint32_t t[4] = {0};

    for (int i = 0; i < N / 2; i++) {
        t[0] = (uint32_t) (GAMMA1 - a->coeffs[2 * i + 0]);
        t[1] = (uint32_t) (GAMMA1 - a->coeffs[2 * i + 1]);

        r[5 * i + 0] = (uint8_t) (t[0]);
        r[5 * i + 1] = (uint8_t) (t[0] >> 8);
        r[5 * i + 2] = (uint8_t) (t[0] >> 16);
        r[5 * i + 2] |= (uint8_t) (t[1] << 4);
        r[5 * i + 3] = (uint8_t) (t[1] >> 4);
        r[5 * i + 4] = (uint8_t) (t[1] >> 12);
    }
}

void poly_z_unpack(Poly *r, uint8_t a[]) {
    for (int i = 0; i < N / 2; i++) {
        r->coeffs[2 * i + 0] = (int32_t) (a[5 * i + 0]);
        r->coeffs[2 * i + 0] |= (int32_t) ((uint32_t) (a[5 * i + 1]) << 8);
        r->coeffs[2 * i + 0] |= (int32_t) ((uint32_t) (a[5 * i + 2]) << 16);
        r->coeffs[2 * i + 0] &= 0xFFFFF;

        r->coeffs[2 * i + 1] = (int32_t) (a[5 * i + 2] >> 4);
        r->coeffs[2 * i + 1] |= (int32_t) ((uint32_t) (a[5 * i + 3]) << 4);
        r->coeffs[2 * i + 1] |= (int32_t) ((uint32_t) (a[5 * i + 4]) << 12);
        r->coeffs[2 * i + 0] &= 0xFFFFF;  // TODO (cyyber): This line has no use, might be removed

        r->coeffs[2 * i + 0] = GAMMA1 - r->coeffs[2 * i + 0];
        r->coeffs[2 * i + 1] = GAMMA1 - r->coeffs[2 * i + 1];
    }
}

void poly_w1_pack(uint8_t r[], Poly *a) {
    for (int i = 0; i < N / 2; i++) {
        r[i] = (uint8_t) (a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4));
    }
}
