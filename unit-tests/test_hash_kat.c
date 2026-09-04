/* Known-answer tests for the hash primitives the signer is built on.
 *
 * SHAKE-128 / SHAKE-256 expectations come from Python's hashlib (the SHA-3
 * standard implementation); Keccak-256 expectations use the legacy 0x01 padding
 * and are anchored on the canonical empty-string digest
 * c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470.
 *
 * The longer cases deliberately squeeze past one sponge rate (168 bytes for
 * SHAKE-128, 136 for SHAKE-256) so the squeeze-refill path is exercised too.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "keccak256.h"
#include "shake128.h"
#include "shake256.h"

static void assert_hex_equal(const uint8_t *got, const char *expect_hex, size_t len) {
    char hex[2 * 200 + 1];
    assert_true(len <= 200);
    for (size_t i = 0; i < len; i++) {
        static const char d[] = "0123456789abcdef";
        hex[2 * i] = d[got[i] >> 4];
        hex[2 * i + 1] = d[got[i] & 0x0f];
    }
    hex[2 * len] = '\0';
    assert_string_equal(hex, expect_hex);
}

static void shake128_of(const char *msg, uint8_t *out, size_t outlen) {
    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, (const uint8_t *) msg, strlen(msg));
    shake128_finalize(&ctx);
    shake128_squeeze(&ctx, out, outlen);
    shake128_clear(&ctx);
}

static void shake256_of(const char *msg, uint8_t *out, size_t outlen) {
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, (const uint8_t *) msg, strlen(msg));
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, outlen);
    shake256_clear(&ctx);
}

static void keccak256_of(const char *msg, uint8_t out[32]) {
    keccak256_ctx ctx;
    keccak256_init(&ctx);
    keccak256_absorb(&ctx, (const uint8_t *) msg, strlen(msg));
    keccak256_finalize(&ctx);
    keccak256_squeeze(&ctx, out);
    keccak256_clear(&ctx);
}

static void test_keccak256_kat(void **state) {
    (void) state;
    uint8_t out[32];

    /* The transaction sighash uses legacy Keccak-256; a drift to SHA3-256
     * padding would change every signature the device produces. */
    keccak256_of("", out);
    assert_hex_equal(out, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", 32);

    keccak256_of("abc", out);
    assert_hex_equal(out, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", 32);

    keccak256_of("The quick brown fox jumps over the lazy dog", out);
    assert_hex_equal(out, "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", 32);
}

static void test_shake128_kat(void **state) {
    (void) state;
    uint8_t out[168];

    shake128_of("", out, 32);
    assert_hex_equal(out, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", 32);

    shake128_of("abc", out, 32);
    assert_hex_equal(out, "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8", 32);

    /* 168 bytes == one full SHAKE-128 rate: crosses the refill boundary. */
    shake128_of("abc", out, sizeof(out));
    assert_hex_equal(
        out,
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd0665687"
        "06f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2252aa94db9c538956c"
        "717dc2bed4f232a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4a0ed296c801"
        "f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49acc29082f5647584e",
        sizeof(out));
}

static void test_shake256_kat(void **state) {
    (void) state;
    uint8_t out[136];

    shake256_of("", out, 32);
    assert_hex_equal(out, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f", 32);

    shake256_of("abc", out, 32);
    assert_hex_equal(out, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739", 32);

    /* 136 bytes == one full SHAKE-256 rate: crosses the refill boundary. */
    shake256_of("abc", out, sizeof(out));
    assert_hex_equal(
        out,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c05"
        "27e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c5657724ada64d2470157b3c"
        "dc288620944d78dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e8a2d7ec71a"
        "7cc29",
        sizeof(out));
}

static void test_incremental_absorb_matches_single(void **state) {
    (void) state;
    uint8_t one[32], many[32];

    shake256_of("The quick brown fox jumps over the lazy dog", one, sizeof(one));

    /* Absorbing in several calls must equal absorbing in one; the signer relies
     * on this when it streams tr || pre || message into mu. */
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, (const uint8_t *) "The quick brown ", 16);
    shake256_absorb(&ctx, (const uint8_t *) "fox jumps over ", 15);
    shake256_absorb(&ctx, (const uint8_t *) "the lazy dog", 12);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, many, sizeof(many));
    shake256_clear(&ctx);

    assert_memory_equal(one, many, sizeof(one));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_keccak256_kat),
        cmocka_unit_test(test_shake128_kat),
        cmocka_unit_test(test_shake256_kat),
        cmocka_unit_test(test_incremental_absorb_matches_single),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
