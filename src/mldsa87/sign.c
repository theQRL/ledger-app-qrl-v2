#include "sign.h"
#include <string.h>
#include "utils.h"
#include "cx.h"
#include "shake128.h"
#include "shake256.h"
#include "polyvec.h"
#include "os_nvm.h"
#include "os_pic.h"
#include "globals.h"
#include "os.h"
#include <inttypes.h>

typedef union {
    Poly temp_poly;
    uint8_t buf_squeeze[850];
} u_temp_poly_buffer_squeeze;

u_temp_poly_buffer_squeeze ubuf;

/* Kept separate from ubuf: gamma1 unpacking needs the sampled polynomial and
 * the SHAKE output live at the same time. */
static uint8_t gamma1_buffer[POLY_UNIFORM_GAMMA1_N_BLOCKS * STREAM_256_BLOCK_BYTES];

static void shake256_squeeze_volatile(shake256_ctx *ctx, volatile uint8_t *out, size_t outlen) {
    if (!ctx->squeezing) shake256_finalize(ctx);
    uint8_t temp = 0;
    // uint8_t temp[CTILDE_BYTES] = {0};
    explicit_bzero(&ubuf.buf_squeeze, sizeof(ubuf.buf_squeeze));
    for (size_t i = 0; i < outlen; i++) {
        temp = (ctx->s[ctx->pos / 8] >> (8 * (ctx->pos % 8))) & 0xFF;
        ubuf.buf_squeeze[i] = temp;
        // nvm_write((void*)&out[i], &temp, sizeof(uint8_t));
        if (++ctx->pos == SHAKE256_RATE) {
            keccakf_256(ctx->s);
            ctx->pos = 0;
        }
    }
    nvm_write((void *) &out[0], &ubuf.buf_squeeze[0], outlen);
}

static void combined_method(volatile PolyVecK *t1,
                            volatile PolyVecL *s1hat,
                            uint8_t rho[SEED_BYTES]) {
    uint32_t aLen;
    uint32_t bufLen;
    int32_t poly_buffer[256] = {0};
    Poly t_poly;
    for (int i = 0; i < K; i++) {
        // memmove(&ubuf.temp_poly, (const Poly *) &t1->vec[i], sizeof(Poly));
        explicit_bzero(&t_poly, sizeof(t_poly));
        for (int j = 0; j < L; j++) {
            explicit_bzero(poly_buffer, sizeof(poly_buffer));
            // uint8_t buf[POLY_UNIFORM_N_BLOCKS*STREAM_128_BLOCK_BYTES + 2] = {0};

            shake128_ctx ctx;
            shake128_init(&ctx);
            shake128_absorb(&ctx, rho, SEED_BYTES);
            uint16_t nonce = ((uint16_t) i << 8) + (uint16_t) j;
            uint8_t nonces[2] = {(uint8_t) (nonce), (uint8_t) (nonce >> 8)};
            shake128_absorb(&ctx, nonces, 2);
            shake128_finalize(&ctx);
            explicit_bzero(ubuf.buf_squeeze, sizeof(ubuf.buf_squeeze));
            shake128_squeeze(&ctx,
                             ubuf.buf_squeeze,
                             POLY_UNIFORM_N_BLOCKS * STREAM_128_BLOCK_BYTES + 2);

            aLen = N;
            bufLen = POLY_UNIFORM_N_BLOCKS * STREAM_128_BLOCK_BYTES + 2;
            uint32_t ctr = 0, pos = 0, t = 0;
            while (ctr < aLen && pos + 3 <= bufLen) {
                t = (uint32_t) (ubuf.buf_squeeze[pos]);
                t |= (uint32_t) (ubuf.buf_squeeze[pos + 1]) << 8;
                t |= (uint32_t) (ubuf.buf_squeeze[pos + 2]) << 16;
                t &= 0x7fffff;

                pos += 3;

                if (t < Q_CONST) {
                    poly_buffer[ctr] = (int32_t) t;
                    ctr++;
                }
            }

            bufLen = POLY_UNIFORM_N_BLOCKS * STREAM_128_BLOCK_BYTES;
            while (ctr < N) {
                size_t off = bufLen % 3;
                if (off != 0) {
                    memmove(ubuf.buf_squeeze, ubuf.buf_squeeze + bufLen - off, off);
                }
                shake128_squeeze(&ctx, ubuf.buf_squeeze + off, STREAM_128_BLOCK_BYTES);
                aLen = N - ctr;
                bufLen = STREAM_128_BLOCK_BYTES + off;
                uint32_t ctrNew = 0;
                pos = 0;
                while (ctrNew < aLen && pos + 3 <= bufLen) {
                    t = (uint32_t) (ubuf.buf_squeeze[pos]);
                    t |= (uint32_t) (ubuf.buf_squeeze[pos + 1]) << 8;
                    t |= (uint32_t) (ubuf.buf_squeeze[pos + 2]) << 16;
                    t &= 0x7fffff;

                    pos += 3;

                    if (t < Q_CONST) {
                        poly_buffer[ctrNew + ctr] = (int32_t) t;
                        ctrNew++;
                    }
                }
                ctr += ctrNew;
            }
            shake128_clear(&ctx);

            memmove(&ubuf.temp_poly, (const Poly *) &t1->vec[i], sizeof(Poly));
            if (j == 0) {
                for (int k = 0; k < N; k++) {
                    int32_t t2 = 0;
                    int64_t a = ((int64_t) (poly_buffer[k]) * (int64_t) (s1hat->vec[j].coeffs[k]));
                    t2 = (int32_t) ((int64_t) (int32_t) a * Q_INV);
                    t2 = (int32_t) ((a - (int64_t) t2 * Q_CONST) >> 32);
                    ubuf.temp_poly.coeffs[k] = t2;
                    // nvm_write((void*)&t1->vec[i].coeffs[k], &t2, sizeof(int32_t));
                }
            } else {
                for (int k = 0; k < N; k++) {
                    int32_t t3 = 0;
                    int64_t a = ((int64_t) (poly_buffer[k]) * (int64_t) (s1hat->vec[j].coeffs[k]));
                    t3 = (int32_t) ((int64_t) (int32_t) a * Q_INV);
                    t3 = (int32_t) ((a - (int64_t) t3 * Q_CONST) >> 32);
                    t_poly.coeffs[k] = t3;
                }
                for (int k = 0; k < N; k++) {
                    // temp = t1->vec[i].coeffs[k] + t_poly.coeffs[k];
                    ubuf.temp_poly.coeffs[k] = ubuf.temp_poly.coeffs[k] + t_poly.coeffs[k];
                    // counter++;
                    // nvm_write((void*)&t1->vec[i].coeffs[k], &temp, sizeof(int32_t));
                }
            }
            nvm_write((void *) &t1->vec[i], &ubuf.temp_poly, sizeof(Poly));
        }
        // nvm_write((void*)&t1->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

typedef union {
    PolyVecL s1hat;
    PolyVecK t0;
} union_s1hat_t0;

static void poly_vec_k_reduce_volatile(volatile PolyVecK *v) {
    for (int i = 0; i < K; ++i) {
        memmove(&ubuf.temp_poly, (const Poly *) &v->vec[i], sizeof(Poly));
        for (int j = 0; j < N; ++j) {
            int32_t t = 0;
            int32_t a = v->vec[i].coeffs[j];

            t = (a + (1 << 22)) >> 23;
            t = a - t * Q_CONST;
            ubuf.temp_poly.coeffs[j] = t;
        }
        nvm_write((void *) &v->vec[i], (void *) &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_k_inv_ntt_to_mont_volatile(volatile PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &v->vec[i], sizeof(Poly));
        uint32_t count = 0, start = 0, j = 0, k = 0;
        int32_t zeta = 0, t = 0;
        int32_t f = (int32_t) 41978;

        k = 256;

        int32_t temp = 0;

        for (count = 1; count < N; count <<= 1) {
            for (start = 0; start < N; start = (j + count)) {
                k--;
                zeta = -ZETAS[k];
                for (j = start; j < (start + count); j++) {
                    t = ubuf.temp_poly.coeffs[j];

                    temp = t + ubuf.temp_poly.coeffs[j + count];
                    ubuf.temp_poly.coeffs[j] = temp;
                    // nvm_write((void*)&v->vec[i].coeffs[j], &temp, sizeof(int32_t));

                    temp = t - ubuf.temp_poly.coeffs[j + count];
                    ubuf.temp_poly.coeffs[j + count] = temp;
                    // nvm_write((void*)&v->vec[i].coeffs[j+count], &temp,
                    // sizeof(int32_t));
                    int32_t t2 = 0;
                    int64_t a = (int64_t) zeta * (int64_t) ubuf.temp_poly.coeffs[j + count];
                    t2 = (int32_t) ((int64_t) (int32_t) a * Q_INV);
                    t2 = (int32_t) ((a - (int64_t) t2 * Q_CONST) >> 32);
                    ubuf.temp_poly.coeffs[j + count] = t2;
                    // nvm_write((void*)&v->vec[i].coeffs[j+count], &t2, sizeof(int32_t));
                }
            }
        }

        for (j = 0; j < N; ++j) {
            int32_t t3 = 0;
            int64_t a = (int64_t) f * (int64_t) ubuf.temp_poly.coeffs[j];
            t3 = (int32_t) ((int64_t) (int32_t) a * Q_INV);
            t3 = (int32_t) ((a - (int64_t) t3 * Q_CONST) >> 32);
            ubuf.temp_poly.coeffs[j] = t3;
            // nvm_write((void*)&v->vec[i].coeffs[j], &t3, sizeof(int32_t));
        }
        nvm_write((void *) &v->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_k_add_volatile(volatile PolyVecK *w, volatile PolyVecK *v) {
    // int32_t temp = 0;
    for (int i = 0; i < K; ++i) {
        memmove(&ubuf.temp_poly, (const Poly *) &w->vec[i], sizeof(Poly));
        for (int j = 0; j < N; ++j) {
            ubuf.temp_poly.coeffs[j] = ubuf.temp_poly.coeffs[j] + v->vec[i].coeffs[j];
        }
        nvm_write((void *) &w->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_k_ntt_volatile(volatile PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &v->vec[i], sizeof(Poly));
        uint32_t count = 0, start = 0, j = 0, k = 0;
        int32_t zeta = 0, t = 0;

        k = 0;
        for (count = 128; count > 0; count >>= 1) {
            for (start = 0; start < N; start = j + count) {
                k++;
                zeta = ZETAS[k];
                for (j = start; j < start + count; j++) {
                    int32_t t2 = 0;
                    int64_t a_reduce = (int64_t) zeta * (int64_t) ubuf.temp_poly.coeffs[j + count];
                    t2 = (int32_t) ((int64_t) (int32_t) a_reduce * Q_INV);
                    t2 = (int32_t) ((a_reduce - (int64_t) t2 * Q_CONST) >> 32);
                    t = t2;
                    // t = montgomery_reduce((int64_t)zeta * (int64_t)(*a)[j+count]);
                    ubuf.temp_poly.coeffs[j + count] = ubuf.temp_poly.coeffs[j] - t;
                    // nvm_write((void *)&v->vec[i].coeffs[j+count], &temp,
                    // sizeof(int32_t));
                    // (*a)[j+count] = v->vec[i].[j] - t;
                    ubuf.temp_poly.coeffs[j] = ubuf.temp_poly.coeffs[j] + t;
                    // nvm_write((void *)&v->vec[i].coeffs[j], &temp, sizeof(int32_t));
                    // (*a)[j] = v->vec[i].[j] + t;
                }
            }
        }
        nvm_write((void *) &v->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_k_c_addq_volatile(volatile PolyVecK *v) {
    for (int i = 0; i < K; ++i) {
        memmove(&ubuf.temp_poly, (const Poly *) &v->vec[i], sizeof(Poly));
        for (int j = 0; j < N; ++j) {
            int32_t a = ubuf.temp_poly.coeffs[j];
            a += (a >> 31) & Q_CONST;
            ubuf.temp_poly.coeffs[j] = a;
        }
        nvm_write((void *) &v->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_k_power2_round_volatile(volatile PolyVecK *v1,
                                             volatile PolyVecK *v0,
                                             volatile PolyVecK *v) {
    int32_t temp = 0;

    for (int i = 0; i < K; ++i) {
        memmove(&ubuf.temp_poly, (const Poly *) &v0->vec[i], sizeof(Poly));
        for (int j = 0; j < N; ++j) {
            int32_t a1 = 0;

            a1 = (v->vec[i].coeffs[j] + (1 << (D - 1)) - 1) >> D;
            temp = v->vec[i].coeffs[j] - (a1 << D);
            ubuf.temp_poly.coeffs[j] = temp;
            // nvm_write((void*)&v0->vec[i].coeffs[j], &temp, sizeof(int32_t));
            // v0->vec[i].coeffs[j] = v->vec[i].coeffs[j] - (a1 << D);
            // ubuf.temp_poly.coeffs[j] = a1;
        }
        nvm_write((void *) &v0->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }

    for (int i = 0; i < K; ++i) {
        memmove(&ubuf.temp_poly, (const Poly *) &v1->vec[i], sizeof(Poly));
        for (int j = 0; j < N; ++j) {
            int32_t a1 = 0;

            a1 = (v->vec[i].coeffs[j] + (1 << (D - 1)) - 1) >> D;
            // temp = v->vec[i].coeffs[j] - (a1 << D);
            // nvm_write((void*)&v0->vec[i].coeffs[j], &temp, sizeof(int32_t));
            // v0->vec[i].coeffs[j] = v->vec[i].coeffs[j] - (a1 << D);
            ubuf.temp_poly.coeffs[j] = a1;
        }
        nvm_write((void *) &v1->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_k_power2_round_volatile_keypair(volatile PolyVecK *v1, volatile PolyVecK *v) {
    for (int i = 0; i < K; ++i) {
        memmove(&ubuf.temp_poly, (const Poly *) &v1->vec[i], sizeof(Poly));
        for (int j = 0; j < N; ++j) {
            int32_t a1 = 0;

            a1 = (v->vec[i].coeffs[j] + (1 << (D - 1)) - 1) >> D;
            // v0->vec[i].coeffs[j] = v->vec[i].coeffs[j] - (a1 << D);
            ubuf.temp_poly.coeffs[j] = a1;
        }
        nvm_write((void *) &v1->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void pack_pk_volatile(uint8_t rho[SEED_BYTES], volatile PolyVecK *t1) {
    uint8_t temp1[SEED_BYTES] = {0};
    for (int i = 0; i < SEED_BYTES; ++i) {
        temp1[i] = rho[i];
    }
    nvm_write((void *) &N_storage.pk[0], (void *) &temp1[0], sizeof(uint8_t) * SEED_BYTES);
    uint8_t temp2[POLY_T1_PACKED_BYTES] = {0};
    for (int b = 0; b < K; b++) {
        explicit_bzero(&temp2, sizeof(temp2));
        for (int i = 0; i < N / 4; i++) {
            temp2[5 * i + 0] = (uint8_t) (t1->vec[b].coeffs[4 * i + 0] >> 0);

            temp2[5 * i + 1] = (uint8_t) ((t1->vec[b].coeffs[4 * i + 0] >> 8) |
                                          (t1->vec[b].coeffs[4 * i + 1] << 2));

            temp2[5 * i + 2] = (uint8_t) ((t1->vec[b].coeffs[4 * i + 1] >> 6) |
                                          (t1->vec[b].coeffs[4 * i + 2] << 4));

            temp2[5 * i + 3] = (uint8_t) ((t1->vec[b].coeffs[4 * i + 2] >> 4) |
                                          (t1->vec[b].coeffs[4 * i + 3] << 6));

            temp2[5 * i + 4] = (uint8_t) ((t1->vec[b].coeffs[4 * i + 3] >> 2));
        }
        nvm_write((void *) &N_storage.pk[SEED_BYTES + b * POLY_T1_PACKED_BYTES],
                  (void *) &temp2[0],
                  sizeof(uint8_t) * POLY_T1_PACKED_BYTES);
    }
}

ErrorCode crypto_sign_keypair(uint8_t (*seed)[SEED_BYTES]) {
    uint8_t rho[SEED_BYTES] = {0};
    uint8_t key[SEED_BYTES] = {0};
    uint8_t rhoPrime[CRH_BYTES] = {0};

    // union_s1hat_t0 u;

    PolyVecL s1;
    explicit_bzero(&s1, sizeof(s1));
    PolyVecK s2;
    explicit_bzero(&s2, sizeof(s2));

    if (seed == NULL) {
        uint8_t seed_new[SEED_BYTES] = {0};
        cx_rng(seed_new, SEED_BYTES);
        seed = &seed_new;
    }
    /* Expand 32 bytes of randomness into rho, rhoprime and key */
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, *seed, SEED_BYTES);
    uint8_t extraData[2] = {K, L};
    shake256_absorb(&ctx, extraData, 2);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, rho, SEED_BYTES);
    shake256_squeeze(&ctx, rhoPrime, CRH_BYTES);
    shake256_squeeze(&ctx, key, SEED_BYTES);
    shake256_clear(&ctx);

    int err = 0;
    /* Sample short vectors s1 and s2 */
    err = poly_vec_l_uniform_eta(&s1, &rhoPrime, 0);
    if (err != 0) {
        return err;
    }
    err = poly_vec_k_uniform_eta(&s2, &rhoPrime, L);
    if (err != 0) {
        return err;
    }
    /* Matrix-vector multiplication */
    // u.s1hat = s1;
    poly_vec_l_ntt(&s1);
    combined_method(&N_storage.t1, &s1, rho);
    poly_vec_k_reduce_volatile(&N_storage.t1);
    poly_vec_k_inv_ntt_to_mont_volatile(&N_storage.t1);

    // /* Add noise vector s2 */
    poly_vec_k_add_volatile(&N_storage.t1, &s2);

    // /* Extract t1 and write public key */
    poly_vec_k_c_addq_volatile(&N_storage.t1);
    poly_vec_k_power2_round_volatile_keypair(&N_storage.t1, &N_storage.t1);
    pack_pk_volatile(rho, &N_storage.t1);

    return 0;
}

static void poly_vec_l_uniform_gamma1_volatile(volatile PolyVecL *v,
                                               uint8_t seed[CRH_BYTES],
                                               uint16_t nonce) {
    // static uint8_t buf[POLY_UNIFORM_GAMMA1_N_BLOCKS * STREAM_256_BLOCK_BYTES] = {0};
    for (int j = (uint16_t) 0; j < L; j++) {
        memmove(&ubuf.temp_poly, (const Poly *) &v->vec[j], sizeof(Poly));
        explicit_bzero(gamma1_buffer, sizeof(gamma1_buffer));

        shake256_ctx ctx;
        shake256_init(&ctx);
        shake256_absorb(&ctx, seed, CRH_BYTES);
        uint16_t nonce_val = L * nonce + j;
        uint8_t nonces[2] = {(uint8_t) nonce_val, (uint8_t) (nonce_val >> 8)};
        shake256_absorb(&ctx, nonces, 2);
        shake256_finalize(&ctx);
        shake256_squeeze(&ctx, gamma1_buffer, sizeof(gamma1_buffer));
        shake256_clear(&ctx);

        for (int i = 0; i < N / 2; i++) {
            ubuf.temp_poly.coeffs[2 * i + 0] = (int32_t) (gamma1_buffer[5 * i + 0]);

            ubuf.temp_poly.coeffs[2 * i + 0] =
                ubuf.temp_poly.coeffs[2 * i + 0] |
                (int32_t) ((uint32_t) (gamma1_buffer[5 * i + 1]) << 8);

            ubuf.temp_poly.coeffs[2 * i + 0] =
                ubuf.temp_poly.coeffs[2 * i + 0] |
                (int32_t) ((uint32_t) (gamma1_buffer[5 * i + 2]) << 16);

            ubuf.temp_poly.coeffs[2 * i + 0] = ubuf.temp_poly.coeffs[2 * i + 0] & 0xFFFFF;

            ubuf.temp_poly.coeffs[2 * i + 1] = (int32_t) (gamma1_buffer[5 * i + 2] >> 4);

            ubuf.temp_poly.coeffs[2 * i + 1] =
                ubuf.temp_poly.coeffs[2 * i + 1] |
                (int32_t) ((uint32_t) (gamma1_buffer[5 * i + 3]) << 4);

            ubuf.temp_poly.coeffs[2 * i + 1] =
                ubuf.temp_poly.coeffs[2 * i + 1] |
                (int32_t) ((uint32_t) (gamma1_buffer[5 * i + 4]) << 12);

            ubuf.temp_poly.coeffs[2 * i + 0] = ubuf.temp_poly.coeffs[2 * i + 0] & 0xFFFFF;

            ubuf.temp_poly.coeffs[2 * i + 0] = GAMMA1 - ubuf.temp_poly.coeffs[2 * i + 0];

            ubuf.temp_poly.coeffs[2 * i + 1] = GAMMA1 - ubuf.temp_poly.coeffs[2 * i + 1];
        }
        nvm_write((void *) &v->vec[j], &ubuf.temp_poly, sizeof(Poly));
        explicit_bzero(gamma1_buffer, sizeof(gamma1_buffer));
    }
}

static void poly_vec_l_ntt_volatile(volatile PolyVecL *v) {
    for (int i = 0; i < L; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &v->vec[i], sizeof(Poly));
        uint32_t count = 0, start = 0, j = 0, k = 0;
        int32_t zeta = 0, t = 0;

        k = 0;
        for (count = 128; count > 0; count >>= 1) {
            for (start = 0; start < N; start = j + count) {
                k++;
                zeta = ZETAS[k];
                for (j = start; j < start + count; j++) {
                    int32_t t1 = 0;
                    int64_t a_reduce = (int64_t) zeta * (int64_t) ubuf.temp_poly.coeffs[j + count];
                    t1 = (int32_t) ((int64_t) (int32_t) a_reduce * Q_INV);
                    t1 = (int32_t) ((a_reduce - (int64_t) t1 * Q_CONST) >> 32);
                    t = t1;
                    ubuf.temp_poly.coeffs[j + count] = ubuf.temp_poly.coeffs[j] - t;
                    ubuf.temp_poly.coeffs[j] = ubuf.temp_poly.coeffs[j] + t;
                }
            }
        }
        nvm_write((void *) &v->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_k_decompose_volatile(volatile PolyVecK *v1,
                                          volatile PolyVecK *v0,
                                          volatile PolyVecK *v) {
    int32_t temp = 0;
    // static Poly ubuf.temp_poly_2;

    for (int i = 0; i < K; i++) {
        // memmove(&ubuf.temp_poly, (const Poly *) &v1->vec[i], sizeof(Poly));
        memmove(&ubuf.temp_poly, (const Poly *) &v0->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            int32_t a1_result = (v->vec[i].coeffs[j] + 127) >> 7;
            a1_result = (a1_result * 1025 + (1 << 21)) >> 22;
            a1_result &= 15;

            temp = v->vec[i].coeffs[j] - a1_result * 2 * GAMMA2;
            ubuf.temp_poly.coeffs[j] = temp;
            // nvm_write((void *)&v0->vec[i].coeffs[j], &temp, sizeof(int32_t));
            temp = ubuf.temp_poly.coeffs[j] -
                   ((((Q_CONST - 1) / 2 - ubuf.temp_poly.coeffs[j]) >> 31) & Q_CONST);
            ubuf.temp_poly.coeffs[j] = temp;
            // nvm_write((void *)&v0->vec[i].coeffs[j], &temp, sizeof(int32_t));
            // ubuf.temp_poly.coeffs[j] = a1_result;
            // nvm_write((void *)&v1->vec[i].coeffs[j], &a1_result, sizeof(int32_t));
        }
        // nvm_write((void*)&v1->vec[i], &ubuf.temp_poly, sizeof(Poly));
        nvm_write((void *) &v0->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }

    for (int i = 0; i < K; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &v1->vec[i], sizeof(Poly));
        // memmove(&ubuf.temp_poly_2, &v0->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            int32_t a1_result = (v->vec[i].coeffs[j] + 127) >> 7;
            a1_result = (a1_result * 1025 + (1 << 21)) >> 22;
            a1_result &= 15;

            // temp = v->vec[i].coeffs[j] - a1_result*2*GAMMA2;
            // ubuf.temp_poly_2.coeffs[j] = temp;
            // nvm_write((void *)&v0->vec[i].coeffs[j], &temp, sizeof(int32_t));
            // temp = v0->vec[i].coeffs[j] - ((((Q_CONST-1)/2 - v0->vec[i].coeffs[j]) >> 31) &
            // Q_CONST); ubuf.temp_poly_2.coeffs[j] = temp; nvm_write((void *)&v0->vec[i].coeffs[j],
            // &temp, sizeof(int32_t));
            ubuf.temp_poly.coeffs[j] = a1_result;
            // nvm_write((void *)&v1->vec[i].coeffs[j], &a1_result, sizeof(int32_t));
        }
        nvm_write((void *) &v1->vec[i], &ubuf.temp_poly, sizeof(Poly));
        // nvm_write((void*)&v0->vec[i], &ubuf.temp_poly_2, sizeof(Poly));
    }
}

static void poly_vec_k_pack_w1_volatile(volatile uint8_t *r, volatile PolyVecK *w1) {
    int32_t temp = 0;
    uint8_t temp_buffer[POLY_W1_PACKED_BYTES] = {0};
    for (int i = 0; i < K; i++) {
        explicit_bzero(&temp_buffer, sizeof(temp_buffer));
        for (int j = 0; j < N / 2; j++) {
            temp = (uint8_t) (w1->vec[i].coeffs[2 * j + 0] | (w1->vec[i].coeffs[2 * j + 1] << 4));
            temp_buffer[j] = temp;
            // nvm_write((void *)&r[j + i*POLY_W1_PACKED_BYTES], &temp, sizeof(uint8_t));
        }
        nvm_write((void *) &r[i * POLY_W1_PACKED_BYTES],
                  &temp_buffer[0],
                  sizeof(uint8_t) * POLY_W1_PACKED_BYTES);
    }
}

static void poly_vec_k_pack_w1_volatile_verify(volatile uint8_t r[K * POLY_W1_PACKED_BYTES],
                                               volatile PolyVecK *w1) {
    uint8_t temp_buffer[POLY_W1_PACKED_BYTES] = {0};
    for (int i = 0; i < K; i++) {
        explicit_bzero(&temp_buffer, sizeof(temp_buffer));
        for (int j = 0; j < N / 2; j++) {
            temp_buffer[j] =
                (uint8_t) (w1->vec[i].coeffs[2 * j + 0] | (w1->vec[i].coeffs[2 * j + 1] << 4));
            // r[j + i*POLY_W1_PACKED_BYTES] = (uint8_t)(w1->vec[i].coeffs[2*j+0] |
            // (w1->vec[i].coeffs[2*j+1] << 4));
        }
        nvm_write((void *) &r[i * POLY_W1_PACKED_BYTES],
                  (void *) &temp_buffer[0],
                  sizeof(uint8_t) * POLY_W1_PACKED_BYTES);
    }
}

static void poly_vec_l_pointwise_poly_montgomery_volatile(volatile PolyVecL *r,
                                                          volatile Poly *a,
                                                          volatile PolyVecL *v) {
    for (int i = 0; i < L; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &r->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            int32_t t = 0;
            int64_t a_reduce = (int64_t) (a->coeffs[j]) * (int64_t) (v->vec[i].coeffs[j]);
            t = (int32_t) ((int64_t) (int32_t) a_reduce * Q_INV);
            t = (int32_t) ((a_reduce - (int64_t) t * Q_CONST) >> 32);
            ubuf.temp_poly.coeffs[j] = t;
        }
        nvm_write((void *) &r->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_l_inv_ntt_to_mont_volatile(volatile PolyVecL *v) {
    for (int i = 0; i < L; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &v->vec[i], sizeof(Poly));
        uint32_t count = 0, start = 0, j = 0, k = 0;
        int32_t zeta = 0, t = 0;
        int32_t f = (int32_t) 41978;

        k = 256;
        int32_t temp = 0;
        for (count = 1; count < N; count <<= 1) {
            for (start = 0; start < N; start = j + count) {
                k--;
                zeta = -ZETAS[k];
                for (j = start; j < start + count; j++) {
                    t = ubuf.temp_poly.coeffs[j];
                    temp = t + ubuf.temp_poly.coeffs[j + count];
                    ubuf.temp_poly.coeffs[j] = temp;
                    // nvm_write((void *)&v->vec[i].coeffs[j], &temp, sizeof(int32_t));
                    temp = t - ubuf.temp_poly.coeffs[j + count];
                    ubuf.temp_poly.coeffs[j + count] = temp;
                    // nvm_write((void *)&v->vec[i].coeffs[j+count], &temp,
                    // sizeof(int32_t));
                    int32_t t2 = 0;
                    int64_t a = (int64_t) zeta * (int64_t) ubuf.temp_poly.coeffs[j + count];
                    t2 = (int32_t) ((int64_t) (int32_t) a * Q_INV);
                    t2 = (int32_t) ((a - (int64_t) t2 * Q_CONST) >> 32);
                    ubuf.temp_poly.coeffs[j + count] = t2;
                    // nvm_write((void *)&v->vec[i].coeffs[j+count], &t2,
                    // sizeof(int32_t));
                }
            }
        }

        for (j = 0; j < N; j++) {
            int32_t t3 = 0;
            int64_t a = (int64_t) f * (int64_t) ubuf.temp_poly.coeffs[j];
            t3 = (int32_t) ((int64_t) (int32_t) a * Q_INV);
            t3 = (int32_t) ((a - (int64_t) t3 * Q_CONST) >> 32);
            ubuf.temp_poly.coeffs[j] = t3;
            // nvm_write((void *)&v->vec[i].coeffs[j], &t3, sizeof(int32_t));
        }
        nvm_write((void *) &v->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_l_add_volatile(volatile PolyVecL *w, volatile PolyVecL *v) {
    // int32_t temp = 0;
    for (int i = 0; i < L; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &w->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            ubuf.temp_poly.coeffs[j] = ubuf.temp_poly.coeffs[j] + v->vec[i].coeffs[j];
        }
        nvm_write((void *) &w->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_l_reduce_volatile(volatile PolyVecL *v) {
    for (int i = 0; i < L; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &v->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            int32_t t = 0;

            t = (v->vec[i].coeffs[j] + (1 << 22)) >> 23;
            t = v->vec[i].coeffs[j] - t * Q_CONST;
            ubuf.temp_poly.coeffs[j] = t;
        }
        nvm_write((void *) &v->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_k_sub_volatile(volatile PolyVecK *w,
                                    volatile PolyVecK *u,
                                    volatile PolyVecK *v) {
    // int32_t temp = 0;
    for (int i = 0; i < K; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &w->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            ubuf.temp_poly.coeffs[j] = u->vec[i].coeffs[j] - v->vec[i].coeffs[j];
        }
        nvm_write((void *) &w->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static ErrorCode pack_sig_volatile(volatile uint8_t sig[],
                                   size_t sigb_len,
                                   uint8_t c[CTILDE_BYTES],
                                   volatile PolyVecL *z,
                                   volatile PolyVecK *h) {
    if (sigb_len != CRYPTO_BYTES) {
        return ERR_INVALID_SIGB_LENGTH;
    }
    uint8_t temp1[CTILDE_BYTES] = {0};
    for (int i = 0; i < CTILDE_BYTES; i++) {
        temp1[i] = c[i];
    }
    nvm_write((void *) &sig[0], (void *) &temp1[0], sizeof(uint8_t) * CTILDE_BYTES);

    // uint8_t temp2[POLY_Z_PACKED_BYTES] = {0};
    // int32_t temp = 0;
    uint8_t temp = 0;
    for (int b = 0; b < L; b++) {
        explicit_bzero(&ubuf.buf_squeeze, sizeof(ubuf.buf_squeeze));
        uint32_t t[4] = {0};

        for (int i = 0; i < N / 2; i++) {
            t[0] = (uint32_t) (GAMMA1 - z->vec[b].coeffs[2 * i + 0]);
            t[1] = (uint32_t) (GAMMA1 - z->vec[b].coeffs[2 * i + 1]);

            // temp2[5*i+0] = (uint8_t)(t[0]);
            temp = (uint8_t) (t[0]);
            ubuf.buf_squeeze[5 * i + 0] = temp;
            // nvm_write((void *)&sig[CTILDE_BYTES + b*POLY_Z_PACKED_BYTES + 5*i+0], &temp,
            // sizeof(uint8_t));

            // temp2[5*i+1] = (uint8_t)(t[0] >> 8);
            temp = (uint8_t) (t[0] >> 8);
            ubuf.buf_squeeze[5 * i + 1] = temp;
            // nvm_write((void *)&sig[CTILDE_BYTES + b*POLY_Z_PACKED_BYTES + 5*i+1], &temp,
            // sizeof(uint8_t));

            // temp2[5*i+2] = (uint8_t)(t[0] >> 16);
            temp = (uint8_t) (t[0] >> 16);
            ubuf.buf_squeeze[5 * i + 2] = temp;
            // nvm_write((void *)&sig[CTILDE_BYTES + b*POLY_Z_PACKED_BYTES + 5*i+2], &temp,
            // sizeof(uint8_t));

            // temp2[5*i+2] = temp2[5*i+2] | (uint8_t)(t[1] << 4);
            temp = ubuf.buf_squeeze[5 * i + 2] | (uint8_t) (t[1] << 4);
            ubuf.buf_squeeze[5 * i + 2] = temp;
            // nvm_write((void *)&sig[CTILDE_BYTES + b*POLY_Z_PACKED_BYTES + 5*i+2], &temp,
            // sizeof(uint8_t));

            // temp2[5*i+3] = (uint8_t)(t[1] >> 4);
            temp = (uint8_t) (t[1] >> 4);
            ubuf.buf_squeeze[5 * i + 3] = temp;
            // nvm_write((void *)&sig[CTILDE_BYTES + b*POLY_Z_PACKED_BYTES + 5*i+3], &temp,
            // sizeof(uint8_t));

            // temp2[5*i+4] = (uint8_t)(t[1] >> 12);
            temp = (uint8_t) (t[1] >> 12);
            ubuf.buf_squeeze[5 * i + 4] = temp;
            // nvm_write((void *)&sig[CTILDE_BYTES + b*POLY_Z_PACKED_BYTES + 5*i+4], &temp,
            // sizeof(uint8_t));
        }
        nvm_write((void *) &sig[CTILDE_BYTES + b * POLY_Z_PACKED_BYTES],
                  (void *) &ubuf.buf_squeeze[0],
                  sizeof(uint8_t) * POLY_Z_PACKED_BYTES);
    }

    /* Encode h */
    // temp = 0;
    uint8_t temp3[OMEGA + K] = {0};
    for (int i = 0; i < OMEGA + K; i++) {
        temp3[i] = 0;
    }
    nvm_write((void *) &sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES],
              (void *) &temp3[0],
              sizeof(uint8_t) * (OMEGA + K));

    explicit_bzero(&temp3, sizeof(temp3));
    int32_t k = 0;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            if (h->vec[i].coeffs[j] != 0) {
                temp3[k] = (uint8_t) j;
                k++;
            }
            temp3[OMEGA + i] = (uint8_t) k;
        }
    }
    nvm_write((void *) &sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES],
              (void *) &temp3[0],
              sizeof(uint8_t) * (OMEGA + K));
    return ERR_NONE;
}

static void poly_vec_k_pointwise_poly_montgomery_volatile(volatile PolyVecK *r,
                                                          volatile Poly *a,
                                                          volatile PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &r->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            int32_t t = 0;
            int64_t a_reduce = (int64_t) (a->coeffs[j]) * (int64_t) (v->vec[i].coeffs[j]);
            t = (int32_t) ((int64_t) (int32_t) a_reduce * Q_INV);
            t = (int32_t) ((a_reduce - (int64_t) t * Q_CONST) >> 32);
            ubuf.temp_poly.coeffs[j] = t;
        }
        nvm_write((void *) &r->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static ErrorCode poly_challenge_volatile(volatile Poly *c,
                                         volatile uint8_t seed[],
                                         size_t seed_len) {
    uint32_t pos = 0, b = 0;
    uint8_t buf[SHAKE256_RATE];
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, (const uint8_t *) seed, seed_len);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, buf, SHAKE256_RATE);

    uint64_t signs = 0;
    for (uint64_t i = 0; i < 8; i++) {
        signs |= (uint64_t) buf[i] << (8 * i);
    }
    pos = 8;

    int32_t temp = 0;
    memmove(&ubuf.temp_poly, (const Poly *) c, sizeof(Poly));
    for (int i = 0; i < N; i++) {
        ubuf.temp_poly.coeffs[i] = temp;
        // nvm_write((void *)&c->coeffs[i], &temp, sizeof(int32_t));
    }
    // nvm_write((void *)&c->coeffs[i], &temp, sizeof(int32_t));
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

        temp = ubuf.temp_poly.coeffs[b];
        ubuf.temp_poly.coeffs[i] = temp;
        // nvm_write((void *)&c->coeffs[i], &temp, sizeof(int32_t));
        temp = (int32_t) (1 - 2 * (signs & 1));
        ubuf.temp_poly.coeffs[b] = temp;
        // nvm_write((void *)&c->coeffs[b], &temp, sizeof(int32_t));
        signs >>= 1;
    }
    nvm_write((void *) c, &ubuf.temp_poly, sizeof(Poly));
    shake256_clear(&ctx);
    return 0;
}

static void poly_ntt_volatile(volatile Poly *a) {
    memmove(&ubuf.temp_poly, (const Poly *) a, sizeof(Poly));
    uint32_t count = 0, start = 0, j = 0, k = 0;
    int32_t zeta = 0, t = 0;

    k = 0;
    int32_t temp = 0;
    for (count = 128; count > 0; count >>= 1) {
        for (start = 0; start < N; start = j + count) {
            k++;
            zeta = ZETAS[k];
            for (j = start; j < start + count; j++) {
                int32_t t2 = 0;
                int64_t a_reduce = (int64_t) zeta * (int64_t) ubuf.temp_poly.coeffs[j + count];
                t2 = (int32_t) ((int64_t) (int32_t) a_reduce * Q_INV);
                t2 = (int32_t) ((a_reduce - (int64_t) t2 * Q_CONST) >> 32);
                t = t2;
                temp = ubuf.temp_poly.coeffs[j] - t;
                ubuf.temp_poly.coeffs[j + count] = temp;
                // nvm_write((void *)&a->coeffs[j+count], &temp, sizeof(int32_t));
                temp = ubuf.temp_poly.coeffs[j] + t;
                ubuf.temp_poly.coeffs[j] = temp;
                // nvm_write((void *)&a->coeffs[j], &temp, sizeof(int32_t));
            }
        }
    }
    nvm_write((void *) a, &ubuf.temp_poly, sizeof(Poly));
}

static uint32_t poly_vec_k_make_hint_volatile(volatile PolyVecK *h,
                                              volatile PolyVecK *v0,
                                              volatile PolyVecK *v1) {
    uint32_t s = 0;
    for (int i = 0; i < K; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &h->vec[i], sizeof(Poly));
        uint32_t s2 = 0;
        for (int j = 0; j < N; j++) {
            int32_t temp = 0;
            if (v0->vec[i].coeffs[j] > GAMMA2 || v0->vec[i].coeffs[j] < -GAMMA2 ||
                (v0->vec[i].coeffs[j] == -GAMMA2 && v1->vec[i].coeffs[j] != 0)) {
                temp = 1;
            } else {
                temp = 0;
            }

            ubuf.temp_poly.coeffs[j] = temp;
            // nvm_write((void *)&h->vec[i].coeffs[j], &temp, sizeof(int32_t));
            s2 += (uint32_t) (ubuf.temp_poly.coeffs[j]);
        }
        nvm_write((void *) &h->vec[i], &ubuf.temp_poly, sizeof(Poly));
        s += s2;
    }
    return s;
}

typedef union {
    PolyVecK s2;
    PolyVecL s1hat;
} u_s2_s1hat;

ErrorCode crypto_sign_optimized(const uint32_t bip32_path[],
                                size_t bip32_path_len,
                                uint8_t *message,
                                size_t message_len) {
    // Data validation
    if (message == NULL || message_len == 0) {
        return ERR_INVALID_MESSAGE;
    }
    if (CTX_LEN > 255) {
        return ERR_INVALID_CONTEXT_LENGTH;
    }

    // Message sign prepare
    uint8_t raw_seed[64] = {0};
    cx_err_t err =
        os_derive_bip32_no_throw(CX_CURVE_SECP256K1, bip32_path, bip32_path_len, raw_seed, NULL);
    if (err != 0) {
        return -1;
    }
    uint8_t seed[32] = {0};
    for (int i = 0; i < 32; i++) {
        seed[i] = raw_seed[i];
    }
    explicit_bzero(raw_seed, sizeof(raw_seed));

    // // PRINTF("MLDSA87 SEED: ");
    // for(int i = 0; i < SEED_BYTES; i++) {
    //     // PRINTF("%02x", seed[i]);
    // }
    // // PRINTF("\n");

    uint8_t rnd[RND_BYTES] = {0};
    cx_rng(rnd, RND_BYTES);  // hedged signing (FIPS 204 default)
    uint8_t pre[CTX_LEN + 2] = {0};
    pre[0] = 0;
    pre[1] = (uint8_t) CTX_LEN;
    for (int i = 0; i < CTX_LEN; ++i) {
        pre[i + 2] = CTX[i];
    }

    // From keypair method
    uint8_t tr[TR_BYTES] = {0};
    uint8_t rho[SEED_BYTES] = {0};
    uint8_t key[SEED_BYTES] = {0};
    uint8_t rhoPrime[CRH_BYTES] = {0};

    u_s2_s1hat u;
    PolyVecL s1;
    // PolyVecK s2;

    /* Expand 32 bytes of randomness into rho, rhoprime and key */
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, seed, SEED_BYTES);
    uint8_t extraData[2] = {K, L};
    shake256_absorb(&ctx, extraData, 2);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, rho, SEED_BYTES);
    shake256_squeeze(&ctx, rhoPrime, CRH_BYTES);
    shake256_squeeze(&ctx, key, SEED_BYTES);
    shake256_clear(&ctx);

    /* Sample short vectors s1 and s2 */
    err = poly_vec_l_uniform_eta(&s1, &rhoPrime, 0);
    if (err != 0) {
        return err;
    }
    /* Matrix-vector multiplication */
    u.s1hat = s1;
    poly_vec_l_ntt(&u.s1hat);
    /* Low-RAM matrix/vector multiplication streams its result through NVM. */
    combined_method(&N_storage.t1, &u.s1hat, rho);
    poly_vec_k_reduce_volatile(&N_storage.t1);
    poly_vec_k_inv_ntt_to_mont_volatile(&N_storage.t1);

    /* Add noise vector s2 */
    err = poly_vec_k_uniform_eta(&u.s2, &rhoPrime, L);
    if (err != 0) {
        return err;
    }
    poly_vec_k_add_volatile(&N_storage.t1, &u.s2);

    /* Extract t1 and write public key */
    poly_vec_k_c_addq_volatile(&N_storage.t1);
    poly_vec_k_power2_round_volatile(&N_storage.t1, &N_storage.pack1.t0, &N_storage.t1);
    pack_pk_volatile(rho, &N_storage.t1);

    shake256_init(&ctx);
    shake256_absorb(&ctx, (const uint8_t *) N_storage.pk, CRYPTO_PUBLIC_KEY_BYTES);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, tr, TR_BYTES);
    shake256_clear(&ctx);

    // From signing method
    uint8_t mu[CRH_BYTES] = {0};
    explicit_bzero(rhoPrime, CRH_BYTES);

    uint16_t nonce = 0;
    uint16_t attempts = 0;

    /* Compute mu = CRH(tr, 0, ctxlen, ctx, msg) */
    shake256_init(&ctx);
    shake256_absorb(&ctx, tr, TR_BYTES);
    shake256_absorb(&ctx, pre, CTX_LEN + 2);
    shake256_absorb(&ctx, message, message_len);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, mu, CRH_BYTES);
    shake256_clear(&ctx);

    /* Compute rhoprime = CRH(key, rnd, mu) */
    shake256_init(&ctx);
    shake256_absorb(&ctx, key, SEED_BYTES);
    shake256_absorb(&ctx, rnd, RND_BYTES);
    shake256_absorb(&ctx, mu, CRH_BYTES);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, rhoPrime, CRH_BYTES);
    shake256_clear(&ctx);

    // 	/* Expand matrix and transform vectors */
    poly_vec_l_ntt(&s1);
    poly_vec_k_ntt(&u.s2);
    poly_vec_k_ntt_volatile(&N_storage.pack1.t0);
rej:
    if (attempts >= 814) {
        explicit_bzero(seed, sizeof(seed));
        explicit_bzero(rnd, sizeof(rnd));
        explicit_bzero(key, sizeof(key));
        explicit_bzero(rhoPrime, sizeof(rhoPrime));
        explicit_bzero(mu, sizeof(mu));
        explicit_bzero(&s1, sizeof(s1));
        explicit_bzero(&u, sizeof(u));
        return ERR_INVALID_SIGNATURE;
    }
    attempts++;
    /* Sample intermediate vector y */
    /* Sample directly into the NVM-backed low-RAM workspace. */
    poly_vec_l_uniform_gamma1_volatile(&N_storage.y, rhoPrime, nonce);
    nonce++;

    // 	/* Matrix-vector multiplication */
    int32_t temp_val = 0;

    for (int i = 0; i < L; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &N_storage.z.vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            temp_val = N_storage.y.vec[i].coeffs[j];
            ubuf.temp_poly.coeffs[j] = temp_val;
            // nvm_write((void*)&N_storage.z.vec[i].coeffs[j], &temp_val,
            // sizeof(int32_t));
        }
        nvm_write((void *) &N_storage.z.vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
    poly_vec_l_ntt_volatile(&N_storage.z);
    combined_method(&N_storage.w1, &N_storage.z, rho);
    poly_vec_k_reduce_volatile(&N_storage.w1);
    poly_vec_k_inv_ntt_to_mont_volatile(&N_storage.w1);
    // /* Decompose w and call the random oracle */
    poly_vec_k_c_addq_volatile(&N_storage.w1);
    poly_vec_k_decompose_volatile(&N_storage.w1, &N_storage.w0, &N_storage.w1);
    poly_vec_k_pack_w1_volatile(N_storage.sig, &N_storage.w1);

    shake256_init(&ctx);
    shake256_absorb(&ctx, mu, CRH_BYTES);
    shake256_absorb(&ctx, (const uint8_t *) N_storage.sig, K * POLY_W1_PACKED_BYTES);
    shake256_finalize(&ctx);
    shake256_squeeze_volatile(&ctx, N_storage.sig, CTILDE_BYTES);
    shake256_clear(&ctx);
    poly_challenge_volatile(&N_storage.cp, N_storage.sig, CTILDE_BYTES);
    poly_ntt_volatile(&N_storage.cp);

    // /* Compute z, reject if it reveals secret */
    poly_vec_l_pointwise_poly_montgomery_volatile(&N_storage.z, &N_storage.cp, &s1);
    poly_vec_l_inv_ntt_to_mont_volatile(&N_storage.z);
    poly_vec_l_add_volatile(&N_storage.z, &N_storage.y);
    poly_vec_l_reduce_volatile(&N_storage.z);
    if (poly_vec_l_chk_norm(&N_storage.z, GAMMA1 - BETA) != 0) {
        goto rej;
    }

    // 	/* Check that subtracting cs2 does not change high bits of w and low bits
    // 	 * do not reveal secret information */
    poly_vec_k_pointwise_poly_montgomery_volatile(&N_storage.h, &N_storage.cp, &u.s2);
    poly_vec_k_inv_ntt_to_mont_volatile(&N_storage.h);
    poly_vec_k_sub_volatile(&N_storage.w0, &N_storage.w0, &N_storage.h);
    poly_vec_k_reduce_volatile(&N_storage.w0);
    if (poly_vec_k_chk_norm(&N_storage.w0, GAMMA2 - BETA) != 0) {
        goto rej;
    }

    // /* Compute hints for w1 */
    poly_vec_k_pointwise_poly_montgomery_volatile(&N_storage.h, &N_storage.cp, &N_storage.pack1.t0);
    poly_vec_k_inv_ntt_to_mont_volatile(&N_storage.h);
    poly_vec_k_reduce_volatile(&N_storage.h);
    if (poly_vec_k_chk_norm(&N_storage.h, GAMMA2) != 0) {
        goto rej;
    }

    poly_vec_k_add_volatile(&N_storage.w0, (PolyVecK *) &N_storage.h);
    uint32_t n_ret = poly_vec_k_make_hint_volatile(&N_storage.h, &N_storage.w0, &N_storage.w1);
    if (n_ret > OMEGA) {
        goto rej;
    }
    uint8_t c[CTILDE_BYTES] = {0};
    for (int i = 0; i < CTILDE_BYTES; i++) {
        c[i] = N_storage.sig[i];
    }
    err = pack_sig_volatile(N_storage.sig, CRYPTO_BYTES, c, &N_storage.z, &N_storage.h);
    if (err != 0) {
        return err;
    }
    return 0;
}

static int32_t unpack_sig_volatile(uint8_t (*c)[CTILDE_BYTES],
                                   volatile PolyVecL *z,
                                   volatile PolyVecK *h,
                                   volatile uint8_t sig[CRYPTO_BYTES]) {
    copy_array((uint8_t *) c, CTILDE_BYTES, (uint8_t *) sig, CTILDE_BYTES);

    int32_t temp = 0;
    for (int b = 0; b < L; b++) {
        memmove(&ubuf.temp_poly, (const Poly *) &z->vec[b], sizeof(Poly));
        for (int i = 0; i < N / 2; i++) {
            temp = (int32_t) (sig[CTILDE_BYTES + b * POLY_Z_PACKED_BYTES + 5 * i + 0]);
            ubuf.temp_poly.coeffs[2 * i + 0] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+0], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+0] = (int32_t)(sig[5*i+0]);
            temp = ubuf.temp_poly.coeffs[2 * i + 0] |
                   (int32_t) ((uint32_t) (sig[CTILDE_BYTES + b * POLY_Z_PACKED_BYTES + 5 * i + 1])
                              << 8);
            ubuf.temp_poly.coeffs[2 * i + 0] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+0], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+0] |= (int32_t)((uint32_t)(sig[5*i+1]) << 8);
            temp = ubuf.temp_poly.coeffs[2 * i + 0] |
                   (int32_t) ((uint32_t) (sig[CTILDE_BYTES + b * POLY_Z_PACKED_BYTES + 5 * i + 2])
                              << 16);
            ubuf.temp_poly.coeffs[2 * i + 0] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+0], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+0] |= (int32_t)((uint32_t)(sig[5*i+2]) << 16);
            temp = ubuf.temp_poly.coeffs[2 * i + 0] & 0xFFFFF;
            ubuf.temp_poly.coeffs[2 * i + 0] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+0], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+0] &= 0xFFFFF;

            temp = (int32_t) (sig[CTILDE_BYTES + b * POLY_Z_PACKED_BYTES + 5 * i + 2] >> 4);
            ubuf.temp_poly.coeffs[2 * i + 1] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+1], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+1] = (int32_t)(sig[5*i+2] >> 4);
            temp = ubuf.temp_poly.coeffs[2 * i + 1] |
                   (int32_t) ((uint32_t) (sig[CTILDE_BYTES + b * POLY_Z_PACKED_BYTES + 5 * i + 3])
                              << 4);
            ubuf.temp_poly.coeffs[2 * i + 1] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+1], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+1] |= (int32_t)((uint32_t)(sig[5*i+3]) << 4);
            temp = ubuf.temp_poly.coeffs[2 * i + 1] |
                   (int32_t) ((uint32_t) (sig[CTILDE_BYTES + b * POLY_Z_PACKED_BYTES + 5 * i + 4])
                              << 12);
            ubuf.temp_poly.coeffs[2 * i + 1] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+1], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+1] |= (int32_t)((uint32_t)(sig[5*i+4]) << 12);
            temp = ubuf.temp_poly.coeffs[2 * i + 0] & 0xFFFFF;
            ubuf.temp_poly.coeffs[2 * i + 0] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+0], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+0] &= 0xFFFFF; // TODO (cyyber): This line has no use, might be
            // removed

            temp = GAMMA1 - ubuf.temp_poly.coeffs[2 * i + 0];
            ubuf.temp_poly.coeffs[2 * i + 0] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+0], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+0] = GAMMA1 - z->vec[b].coeffs[2*i+0];
            temp = GAMMA1 - ubuf.temp_poly.coeffs[2 * i + 1];
            ubuf.temp_poly.coeffs[2 * i + 1] = temp;
            // nvm_write((void *)&z->vec[b].coeffs[2*i+1], &temp, sizeof(int32_t));
            // z->vec[b].coeffs[2*i+1] = GAMMA1 - z->vec[b].coeffs[2*i+1];
        }
        nvm_write((void *) &z->vec[b], &ubuf.temp_poly, sizeof(Poly));
    }

    /* Decode h */
    uint32_t k = (uint32_t) 0;
    for (int i = 0; i < K; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &h->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            temp = 0;
            ubuf.temp_poly.coeffs[j] = temp;
            // nvm_write((void *)&h->vec[i].coeffs[j], &temp, sizeof(int32_t));
        }
        nvm_write((void *) &h->vec[i], &ubuf.temp_poly, sizeof(Poly));
        if ((uint32_t) (sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES + OMEGA + i]) < k ||
            sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES + OMEGA + i] > OMEGA) {
            return 1;
        }
        for (uint32_t j = k;
             j < (uint32_t) (sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES + OMEGA + i]);
             j++) {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES + j] <=
                             sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES + j - 1]) {
                return 1;
            }
            temp = 1;
            nvm_write((void *) &h->vec[i].coeffs[sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES + j]],
                      &temp,
                      sizeof(int32_t));
            // h->vec[i].coeffs[sig[j]] = 1;
        }
        k = (uint32_t) (sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES + OMEGA + i]);
    }

    for (int j = k; j < OMEGA; j++) {
        if (sig[CTILDE_BYTES + L * POLY_Z_PACKED_BYTES + j] != 0) {
            return 1;
        }
    }
    return 0;
}

static void poly_vec_k_shift_l_volatile(volatile PolyVecK *v) {
    int32_t temp = 0;
    for (int i = 0; i < K; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &v->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            temp = ubuf.temp_poly.coeffs[j] << D;
            ubuf.temp_poly.coeffs[j] = temp;
            // nvm_write((void *)&v->vec[i].coeffs[j], &temp, sizeof(int32_t));
            // a->coeffs[i] <<= D;
        }
        nvm_write((void *) &v->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

static void poly_vec_k_use_hint_volatile(volatile PolyVecK *w,
                                         volatile PolyVecK *u,
                                         volatile PolyVecK *h) {
    // wuv, bah
    // hint = h
    for (int i = 0; i < K; i++) {
        memmove(&ubuf.temp_poly, (const Poly *) &w->vec[i], sizeof(Poly));
        for (int j = 0; j < N; j++) {
            int32_t a0 = 0, a1 = 0;
            int32_t a = u->vec[i].coeffs[j];
            int32_t ret = 0;

            int32_t a_decompose = (a + 127) >> 7;
            a_decompose = (a_decompose * 1025 + (1 << 21)) >> 22;
            a_decompose &= 15;

            a0 = a - a_decompose * 2 * GAMMA2;
            a0 -= (((Q_CONST - 1) / 2 - a0) >> 31) & Q_CONST;

            a1 = a_decompose;
            if (h->vec[i].coeffs[j] == 0) {
                ret = a1;
            } else if (a0 > 0) {
                ret = (a1 + 1) & 15;
            } else {
                ret = (a1 - 1) & 15;
            }
            ubuf.temp_poly.coeffs[j] = ret;
            // nvm_write((void *)&w->vec[i].coeffs[j], &temp, sizeof(int32_t));
            // b->coeffs[i] = ret;
        }
        nvm_write((void *) &w->vec[i], &ubuf.temp_poly, sizeof(Poly));
    }
}

typedef union {
    PolyVecK s2;
    PolyVecK t0;
} union_s2_t0;

ErrorCode crypto_verify_optimized(const uint32_t bip32_path[],
                                  size_t bip32_path_len,
                                  uint8_t *sig,
                                  size_t sig_len,
                                  uint8_t *message,
                                  size_t message_len,
                                  bool *is_verified) {
    // Data validation
    if (sig == NULL || sig_len == 0) {
        *is_verified = false;
        return ERR_INVALID_SIGNATURE;
    }
    if (message == NULL || message_len == 0) {
        *is_verified = false;
        return ERR_INVALID_MESSAGE;
    }
    if (CTX_LEN > 255) {
        *is_verified = false;
        return ERR_INVALID_CONTEXT_LENGTH;
    }
    if (sig_len != CRYPTO_BYTES) {
        *is_verified = false;
        return ERR_INVALID_SIGNATURE;
    }

    // Message verify prepare
    uint8_t raw_seed[64] = {0};
    cx_err_t err =
        os_derive_bip32_no_throw(CX_CURVE_SECP256K1, bip32_path, bip32_path_len, raw_seed, NULL);
    if (err != 0) {
        *is_verified = false;
        return -1;
    }
    uint8_t seed[32] = {0};
    for (int i = 0; i < 32; i++) {
        seed[i] = raw_seed[i];
    }
    explicit_bzero(raw_seed, sizeof(raw_seed));

    uint8_t pre[CTX_LEN + 2] = {0};
    pre[0] = 0;
    pre[1] = (uint8_t) CTX_LEN;
    for (int i = 0; i < CTX_LEN; ++i) {
        pre[i + 2] = CTX[i];
    }

    // From keypair method
    uint8_t rho[SEED_BYTES] = {0};
    uint8_t key[SEED_BYTES] = {0};
    uint8_t rhoPrime[CRH_BYTES] = {0};

    PolyVecL s1;
    union_s2_t0 u;

    /* Expand 32 bytes of randomness into rho, rhoprime and key */
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, seed, SEED_BYTES);
    uint8_t extraData[2] = {K, L};
    shake256_absorb(&ctx, extraData, 2);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, rho, SEED_BYTES);
    shake256_squeeze(&ctx, rhoPrime, CRH_BYTES);
    shake256_squeeze(&ctx, key, SEED_BYTES);
    shake256_clear(&ctx);

    /* Sample short vectors s1 and s2 */
    err = poly_vec_l_uniform_eta(&s1, &rhoPrime, 0);
    if (err != 0) {
        return err;
    }
    err = poly_vec_k_uniform_eta(&u.s2, &rhoPrime, L);
    if (err != 0) {
        return err;
    }

    /* Matrix-vector multiplication */
    // u.s1hat = s1;
    poly_vec_l_ntt(&s1);
    combined_method(&N_storage.t1, &s1, rho);
    poly_vec_k_reduce_volatile(&N_storage.t1);
    poly_vec_k_inv_ntt_to_mont_volatile(&N_storage.t1);
    /* Add noise vector s2 */
    poly_vec_k_add_volatile(&N_storage.t1, &u.s2);
    /* Extract t1 and write public key */
    poly_vec_k_c_addq_volatile(&N_storage.t1);
    poly_vec_k_power2_round_volatile(&N_storage.t1, &N_storage.pack1.t0, &N_storage.t1);
    pack_pk_volatile(rho, &N_storage.t1);

    // From verify method
    //  uint8_t buf[K * POLY_W1_PACKED_BYTES] = {0};
    uint8_t mu[CRH_BYTES] = {0};
    uint8_t c[CTILDE_BYTES] = {0};
    uint8_t c2[CTILDE_BYTES] = {0};

    if (unpack_sig_volatile(&c, &N_storage.z, &N_storage.h, sig) != 0) {
        *is_verified = false;
        return 0;
    }

    if (poly_vec_l_chk_norm(&N_storage.z, GAMMA1 - BETA) != 0) {
        *is_verified = false;
        return 0;
    }

    /* Compute CRH(H(rho, t1), pre, msg) */
    // shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, (const uint8_t *) N_storage.pk, CRYPTO_PUBLIC_KEY_BYTES);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, mu, TR_BYTES);
    shake256_clear(&ctx);

    shake256_init(&ctx);
    shake256_absorb(&ctx, mu, TR_BYTES);
    shake256_absorb(&ctx, pre, CTX_LEN + 2);
    shake256_absorb(&ctx, message, message_len);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, mu, CRH_BYTES);
    shake256_clear(&ctx);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    err = poly_challenge_volatile(&N_storage.cp, c, CTILDE_BYTES);
    if (err != 0) {
        *is_verified = false;
        return err;
    }

    poly_vec_l_ntt_volatile(&N_storage.z);
    // poly_vec_matrix_expand(&mat, &rho);
    // poly_vec_matrix_pointwise_montgomery(&w1, &mat, &z);
    combined_method(&N_storage.w1, &N_storage.z, rho);

    poly_ntt_volatile(&N_storage.cp);
    poly_vec_k_shift_l_volatile(&N_storage.t1);
    poly_vec_k_ntt_volatile(&N_storage.t1);
    poly_vec_k_pointwise_poly_montgomery_volatile(&N_storage.t1, &N_storage.cp, &N_storage.t1);

    poly_vec_k_sub_volatile(&N_storage.w1, &N_storage.w1, &N_storage.t1);
    poly_vec_k_reduce_volatile(&N_storage.w1);
    poly_vec_k_inv_ntt_to_mont_volatile(&N_storage.w1);

    /* Reconstruct w1 */
    poly_vec_k_c_addq_volatile(&N_storage.w1);
    poly_vec_k_use_hint_volatile(&N_storage.w1, &N_storage.w1, &N_storage.h);
    poly_vec_k_pack_w1_volatile_verify(N_storage.pack1.buf_verify, &N_storage.w1);

    /* Call random oracle and verify challenge */
    shake256_init(&ctx);
    shake256_absorb(&ctx, mu, CRH_BYTES);
    shake256_absorb(&ctx, (const uint8_t *) N_storage.pack1.buf_verify, K * POLY_W1_PACKED_BYTES);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, c2, CTILDE_BYTES);
    shake256_clear(&ctx);

    for (int i = 0; i < CTILDE_BYTES; i++) {
        if (c[i] != c2[i]) {
            *is_verified = false;
            return ERR_NONE;
        }
    }

    *is_verified = true;
    return ERR_NONE;
}

static void nvm_zero(volatile void *dst, size_t len) {
    uint8_t zeros[256] = {0};
    size_t off = 0;
    while (off < len) {
        size_t chunk = (len - off > sizeof(zeros)) ? sizeof(zeros) : (len - off);
        nvm_write((void *) ((uintptr_t) dst + off), zeros, chunk);
        off += chunk;
    }
}

void wipe_nvm_secrets(void) {
    nvm_zero(&N_storage.y, sizeof(PolyVecL));
    nvm_zero(&N_storage.pack1, sizeof(N_storage.pack1));
    nvm_zero(&N_storage.w0, sizeof(PolyVecK));
}
