#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "rlp_decode.h"

// Unsigned QRL v2.0 type-2 sighash preimages (11 RLP fields), generated with
// tests/e2e/qrltx.mjs. chain_id 3151908, nonce 1, tip 1 gwei, fee cap
// 10 gwei, gas 500000, value 0.01, empty data/access_list, descriptor
// 01 00 00, empty extra_params.
static const char VALID_64B_TO[] =
    "02f8658330182401843b9aca008502540be4008307a120b8400838a121a6e4dd8a51e743"
    "7b152fabbc76a173f077132f2c2ed021c7b0991e70da4dba44e9ec00984a90f28dfb0aab"
    "bda1ddc9e98a76ab0acb6644c5e76fbbe8872386f26fc1000080c08301000080";
static const char VALID_CONTRACT_CREATION[] =
    "02e48330182401843b9aca008502540be4008307a12080872386f26fc1000080c0830100"
    "0080";
static const char INVALID_20B_TO[] =
    "02f8388330182401843b9aca008502540be4008307a120940838a121a6e4dd8a51e74377"
    "b152fabbc76a173f0872386f26fc1000080c08301000080";
// 10-field legacy form (no extra_params)
static const char INVALID_LEGACY_10_FIELDS[] =
    "02f89301038477359400850ba43b74008261a894b94f5374fce5edbc8e2a8697c1533167"
    "7e6ebf0b88016345785d8a0000825544f85bf85994b94f5374fce5edbc8e2a8697c15331"
    "677e6ebf0bf842a000000000000000000000000000000000000000000000000000000000"
    "00000000a0000000000000000000000000000000000000000000000000000000000000000"
    "183010000";

static size_t unhex(const char *hex, uint8_t *out, size_t out_len) {
    size_t n = strlen(hex) / 2;
    if (n > out_len) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned int b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t) b;
    }
    return n;
}

static int decode_hex(const char *hex, zond_tx_t *tx) {
    uint8_t buf[600];
    size_t n = unhex(hex, buf, sizeof(buf));
    memset(tx, 0, sizeof(*tx));
    return decode_ledger_tx(buf, n, tx);
}

static void test_decode_valid_64byte_recipient(void **state) {
    (void) state;
    zond_tx_t tx;
    assert_int_equal(decode_hex(VALID_64B_TO, &tx), 0);
    assert_int_equal(tx.descriptor_len, 3);
    assert_int_equal(tx.descriptor[0], 0x01);
    assert_int_equal(tx.descriptor[1], 0x00);
    assert_int_equal(tx.descriptor[2], 0x00);
    assert_int_equal(tx.to[0], 0x08);
    assert_int_equal(tx.to[63], 0xe8);
    assert_int_equal(tx.chain_id_len, 3);
    assert_int_equal(tx.nonce_len, 1);
    assert_int_equal(tx.nonce[0], 0x01);
    assert_false(tx.has_data);
    assert_false(tx.has_access_list);
}

static void test_reject_noncanonical_integer(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    zond_tx_t tx;
    /* nonce 0x01 encoded as 0x81 0x01; grow list payload and total by one. */
    memmove(buf + 8, buf + 7, n - 7);
    buf[2]++;
    buf[7] = 0x81;
    memset(&tx, 0, sizeof(tx));
    assert_int_not_equal(decode_ledger_tx(buf, n + 1, &tx), 0);
}

static void test_decode_contract_creation(void **state) {
    (void) state;
    zond_tx_t tx;
    assert_int_equal(decode_hex(VALID_CONTRACT_CREATION, &tx), 0);
}

static void test_reject_20byte_recipient(void **state) {
    (void) state;
    zond_tx_t tx;
    assert_int_not_equal(decode_hex(INVALID_20B_TO, &tx), 0);
}

static void test_reject_legacy_10_fields(void **state) {
    (void) state;
    zond_tx_t tx;
    assert_int_not_equal(decode_hex(INVALID_LEGACY_10_FIELDS, &tx), 0);
}

// Flip descriptor / extra_params bytes in the valid vector.
static void test_reject_bad_descriptor(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    zond_tx_t tx;
    // descriptor bytes are the 3 bytes before the final empty extra_params
    buf[n - 2] = 0x01;  // 01 00 01
    memset(&tx, 0, sizeof(tx));
    assert_int_not_equal(decode_ledger_tx(buf, n, &tx), 0);
}

static void test_reject_nonempty_extra_params(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    zond_tx_t tx;
    buf[n - 1] = 0x01;  // extra_params = single byte 0x01
    memset(&tx, 0, sizeof(tx));
    assert_int_not_equal(decode_ledger_tx(buf, n, &tx), 0);
}

static void test_reject_wrong_type_byte(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    zond_tx_t tx;
    buf[0] = 0x01;
    memset(&tx, 0, sizeof(tx));
    assert_int_not_equal(decode_ledger_tx(buf, n, &tx), 0);
}

// Regression: fuzzer-found integer overflow. An 8-byte RLP length field of
// 0xff..ff made `1 + len_of_len + len` wrap past the bounds check, driving a
// memcpy of (size_t)-1. Found 2026-09-02 with libFuzzer+ASAN.
static void test_reject_length_overflow(void **state) {
    (void) state;
    uint8_t buf[64];
    memset(buf, 0xff, sizeof(buf));
    buf[0] = 0x02;
    buf[1] = 0xf8;  // list, 1 length byte
    buf[2] = 0x3b;  // payload claims 59 bytes
    zond_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    assert_int_not_equal(decode_ledger_tx(buf, sizeof(buf), &tx), 0);
}

// Regression: nonce and gas fields lacked bounds checks against their
// 8-byte destination buffers.
static void test_reject_oversized_nonce(void **state) {
    (void) state;
    // 11-field list with a 9-byte nonce
    static const char oversized_nonce[] =
        "02f86e83301824890101010101010101010101843b9aca008502540be4008307a120"
        "b8400838a121a6e4dd8a51e7437b152fabbc76a173f077132f2c2ed021c7b0991e70"
        "da4dba44e9ec00984a90f28dfb0aabbda1ddc9e98a76ab0acb6644c5e76fbbe88723"
        "86f26fc1000080c08301000080";
    zond_tx_t tx;
    assert_int_not_equal(decode_hex(oversized_nonce, &tx), 0);
}

static void test_reject_truncated(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    zond_tx_t tx;
    for (size_t cut = 1; cut < n; cut += 7) {
        memset(&tx, 0, sizeof(tx));
        assert_int_not_equal(decode_ledger_tx(buf, n - cut, &tx), 0);
    }
    memset(&tx, 0, sizeof(tx));
    assert_int_not_equal(decode_ledger_tx(buf, 0, &tx), 0);
    assert_int_not_equal(decode_ledger_tx(NULL, n, &tx), 0);
    assert_int_not_equal(decode_ledger_tx(buf, n, NULL), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_decode_valid_64byte_recipient),
        cmocka_unit_test(test_decode_contract_creation),
        cmocka_unit_test(test_reject_noncanonical_integer),
        cmocka_unit_test(test_reject_20byte_recipient),
        cmocka_unit_test(test_reject_legacy_10_fields),
        cmocka_unit_test(test_reject_bad_descriptor),
        cmocka_unit_test(test_reject_nonempty_extra_params),
        cmocka_unit_test(test_reject_wrong_type_byte),
        cmocka_unit_test(test_reject_length_overflow),
        cmocka_unit_test(test_reject_oversized_nonce),
        cmocka_unit_test(test_reject_truncated),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
