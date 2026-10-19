#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "tx_stream.h"

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
// 11-field list with a 9-byte nonce
static const char INVALID_OVERSIZED_NONCE[] =
    "02f86e83301824890101010101010101010101843b9aca008502540be4008307a120"
    "b8400838a121a6e4dd8a51e7437b152fabbc76a173f077132f2c2ed021c7b0991e70"
    "da4dba44e9ec00984a90f28dfb0aabbda1ddc9e98a76ab0acb6644c5e76fbbe88723"
    "86f26fc1000080c08301000080";

// Every vector is replayed with each of these chunk sizes so that RLP headers
// and payloads get split at every possible boundary.
static const size_t CHUNK_SIZES[] = {1, 2, 3, 5, 7, 64, 255, 4096};
#define N_CHUNK_SIZES (sizeof(CHUNK_SIZES) / sizeof(CHUNK_SIZES[0]))

typedef struct {
    tx_stream_t s;
    zond_tx_t tx;
} ctx_t;

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

// Feed `buf` in chunks of `chunk` bytes. Stops early only on error, so a
// FINISHED reported before the last byte turns into ERROR on the next chunk
// (trailing bytes), which is what the device must see as well.
static tx_stream_status_e feed_chunked(ctx_t *c, const uint8_t *buf, size_t n, size_t chunk) {
    tx_stream_status_e st = TX_STREAM_PROCESSING;
    size_t off = 0;
    while (off < n) {
        size_t k = (n - off < chunk) ? n - off : chunk;
        st = tx_stream_feed(&c->s, &c->tx, buf + off, k);
        off += k;
        if (st == TX_STREAM_ERROR) {
            break;
        }
    }
    return st;
}

static tx_stream_status_e feed_hex(ctx_t *c, const char *hex, size_t chunk) {
    uint8_t buf[600];
    size_t n = unhex(hex, buf, sizeof(buf));
    assert_true(n > 0);
    tx_stream_init(&c->s, &c->tx);
    return feed_chunked(c, buf, n, chunk);
}

// Expect ERROR for every chunk size.
static void assert_rejected_all_chunk_sizes(const uint8_t *buf, size_t n) {
    ctx_t c;
    for (size_t ci = 0; ci < N_CHUNK_SIZES; ci++) {
        tx_stream_init(&c.s, &c.tx);
        assert_int_equal(feed_chunked(&c, buf, n, CHUNK_SIZES[ci]), TX_STREAM_ERROR);
    }
}

// --- minimal canonical RLP encoder used to build synthetic vectors ------------

static size_t rlp_hdr(uint8_t *out, bool is_list, size_t len) {
    uint8_t base = is_list ? 0xc0 : 0x80;
    if (len < 56) {
        out[0] = (uint8_t) (base + len);
        return 1;
    }
    size_t len_of_len = 0;
    for (size_t t = len; t > 0; t >>= 8) {
        len_of_len++;
    }
    out[0] = (uint8_t) (base + 55 + len_of_len);
    for (size_t i = 0; i < len_of_len; i++) {
        out[1 + i] = (uint8_t) (len >> (8 * (len_of_len - 1 - i)));
    }
    return 1 + len_of_len;
}

static size_t rlp_str(uint8_t *out, const uint8_t *data, size_t len) {
    if (len == 1 && data[0] <= 0x7f) {
        out[0] = data[0];
        return 1;
    }
    size_t h = rlp_hdr(out, false, len);
    if (len > 0) {
        memcpy(out + h, data, len);
    }
    return h + len;
}

#define SCRATCH_LEN (TX_MAX_TOTAL_LEN + 8192)
static uint8_t g_body[SCRATCH_LEN];
static uint8_t g_tx[SCRATCH_LEN];
static uint8_t g_data[SCRATCH_LEN];

static const uint8_t TO_64B[64] = {
    0x08, 0x38, 0xa1, 0x21, 0xa6, 0xe4, 0xdd, 0x8a, 0x51, 0xe7, 0x43, 0x7b, 0x15, 0x2f, 0xab, 0xbc,
    0x76, 0xa1, 0x73, 0xf0, 0x77, 0x13, 0x2f, 0x2c, 0x2e, 0xd0, 0x21, 0xc7, 0xb0, 0x99, 0x1e, 0x70,
    0xda, 0x4d, 0xba, 0x44, 0xe9, 0xec, 0x00, 0x98, 0x4a, 0x90, 0xf2, 0x8d, 0xfb, 0x0a, 0xab, 0xbd,
    0xa1, 0xdd, 0xc9, 0xe9, 0x8a, 0x76, 0xab, 0x0a, 0xcb, 0x66, 0x44, 0xc5, 0xe7, 0x6f, 0xbb, 0xe8};
static const uint8_t VALUE_0_01[] = {0x23, 0x86, 0xf2, 0x6f, 0xc1, 0x00, 0x00};

// 0x02 || rlp([chain_id, nonce, tip, fee_cap, gas, to, value, data, access_list, descriptor, ""])
// with the same fixed fields as the reference vectors. `access_list` is passed
// as an already RLP-encoded list item (NULL = empty list 0xc0).
static size_t build_tx(uint8_t *out,
                       size_t cap,
                       const uint8_t *to,
                       size_t to_len,
                       const uint8_t *value,
                       size_t value_len,
                       const uint8_t *data,
                       size_t data_len,
                       const uint8_t *access_list_item,
                       size_t access_list_item_len) {
    static const uint8_t chain_id[] = {0x30, 0x18, 0x24};
    static const uint8_t nonce[] = {0x01};
    static const uint8_t tip[] = {0x3b, 0x9a, 0xca, 0x00};
    static const uint8_t fee_cap[] = {0x02, 0x54, 0x0b, 0xe4, 0x00};
    static const uint8_t gas[] = {0x07, 0xa1, 0x20};
    static const uint8_t descriptor[] = {0x01, 0x00, 0x00};
    size_t n = 0;

    n += rlp_str(g_body + n, chain_id, sizeof(chain_id));
    n += rlp_str(g_body + n, nonce, sizeof(nonce));
    n += rlp_str(g_body + n, tip, sizeof(tip));
    n += rlp_str(g_body + n, fee_cap, sizeof(fee_cap));
    n += rlp_str(g_body + n, gas, sizeof(gas));
    n += rlp_str(g_body + n, to, to_len);
    n += rlp_str(g_body + n, value, value_len);
    n += rlp_str(g_body + n, data, data_len);
    if (access_list_item == NULL) {
        g_body[n++] = 0xc0;  // empty access_list
    } else {
        memcpy(g_body + n, access_list_item, access_list_item_len);
        n += access_list_item_len;
    }
    n += rlp_str(g_body + n, descriptor, sizeof(descriptor));
    g_body[n++] = 0x80;  // empty extra_params

    size_t o = 0;
    out[o++] = 0x02;
    o += rlp_hdr(out + o, true, n);
    if (o + n > cap) {
        return 0;
    }
    memcpy(out + o, g_body, n);
    return o + n;
}

static size_t build_simple(uint8_t *out, size_t cap, const uint8_t *data, size_t data_len) {
    return build_tx(out, cap, TO_64B, 64, VALUE_0_01, sizeof(VALUE_0_01), data, data_len, NULL, 0);
}

// --- tests -------------------------------------------------------------------

static void test_builder_matches_reference_vectors(void **state) {
    (void) state;
    uint8_t ref[600];
    size_t ref_n;
    size_t n;

    ref_n = unhex(VALID_CONTRACT_CREATION, ref, sizeof(ref));
    n = build_tx(g_tx, sizeof(g_tx), NULL, 0, VALUE_0_01, sizeof(VALUE_0_01), NULL, 0, NULL, 0);
    assert_int_equal(n, ref_n);
    assert_memory_equal(g_tx, ref, n);

    ref_n = unhex(VALID_64B_TO, ref, sizeof(ref));
    n = build_simple(g_tx, sizeof(g_tx), NULL, 0);
    assert_int_equal(n, ref_n);
    assert_memory_equal(g_tx, ref, n);
}

static void test_valid_64byte_recipient_all_chunk_sizes(void **state) {
    (void) state;
    ctx_t c;
    for (size_t ci = 0; ci < N_CHUNK_SIZES; ci++) {
        assert_int_equal(feed_hex(&c, VALID_64B_TO, CHUNK_SIZES[ci]), TX_STREAM_FINISHED);
        assert_int_equal(c.tx.chain_id_len, 3);
        assert_int_equal(c.tx.chain_id[0], 0x30);
        assert_int_equal(c.tx.chain_id[2], 0x24);
        assert_int_equal(c.tx.nonce_len, 1);
        assert_int_equal(c.tx.nonce[0], 0x01);
        assert_int_equal(c.tx.gas_tip_cap_len, 4);
        assert_int_equal(c.tx.gas_fee_cap_len, 5);
        assert_int_equal(c.tx.gas_len, 3);
        assert_int_equal(c.tx.gas[0], 0x07);
        assert_memory_equal(c.tx.to, TO_64B, 64);
        assert_int_equal(c.tx.value_len, 7);
        assert_memory_equal(c.tx.value, VALUE_0_01, 7);
        assert_false(c.tx.has_data);
        assert_false(c.tx.has_access_list);
        assert_int_equal(c.tx.descriptor_len, 3);
        assert_int_equal(c.tx.descriptor[0], 0x01);
        assert_int_equal(c.tx.descriptor[1], 0x00);
        assert_int_equal(c.tx.descriptor[2], 0x00);
        assert_int_equal(c.s.list_remaining, 0);
    }
}

static void test_contract_creation(void **state) {
    (void) state;
    ctx_t c;
    uint8_t zeros[64] = {0};
    for (size_t ci = 0; ci < N_CHUNK_SIZES; ci++) {
        assert_int_equal(feed_hex(&c, VALID_CONTRACT_CREATION, CHUNK_SIZES[ci]),
                         TX_STREAM_FINISHED);
        // empty `to` (contract creation) leaves the zero-filled buffer
        assert_memory_equal(c.tx.to, zeros, 64);
        assert_int_equal(c.tx.value_len, 7);
        assert_false(c.tx.has_data);
    }
}

static void test_reject_20byte_recipient(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(INVALID_20B_TO, buf, sizeof(buf));
    assert_rejected_all_chunk_sizes(buf, n);
}

static void test_reject_legacy_10_fields(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(INVALID_LEGACY_10_FIELDS, buf, sizeof(buf));
    assert_rejected_all_chunk_sizes(buf, n);
}

static void test_reject_oversized_nonce(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(INVALID_OVERSIZED_NONCE, buf, sizeof(buf));
    ctx_t c;
    assert_rejected_all_chunk_sizes(buf, n);
    // the 9-byte nonce is rejected from its header alone, before any payload:
    // 02 | f8 6e | 83 30 18 24 | 89 ...  -> error exactly at the 0x89 prefix
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(tx_stream_feed(&c.s, &c.tx, buf, 7), TX_STREAM_PROCESSING);
    assert_int_equal(tx_stream_feed(&c.s, &c.tx, buf + 7, 1), TX_STREAM_ERROR);
}

// nonce 0x01 encoded as 0x81 0x01 instead of the single byte 0x01.
static void test_reject_noncanonical_single_byte(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    memmove(buf + 8, buf + 7, n - 7);
    buf[2]++;  // outer list payload grows by one
    buf[7] = 0x81;
    assert_rejected_all_chunk_sizes(buf, n + 1);
}

static void test_reject_leading_zero_in_integer(void **state) {
    (void) state;
    uint8_t value[] = {0x00, 0x23, 0x86};
    size_t n = build_tx(g_tx, sizeof(g_tx), TO_64B, 64, value, sizeof(value), NULL, 0, NULL, 0);
    assert_rejected_all_chunk_sizes(g_tx, n);

    // a lone zero byte (encoded as itself) is a leading zero as well
    uint8_t buf[600];
    n = unhex(VALID_64B_TO, buf, sizeof(buf));
    assert_int_equal(buf[7], 0x01);  // nonce
    buf[7] = 0x00;
    assert_rejected_all_chunk_sizes(buf, n);

    // but a leading zero inside `data` is fine: it is not an integer
    const uint8_t data[] = {0x00, 0x01, 0x02, 0x03};
    n = build_simple(g_tx, sizeof(g_tx), data, sizeof(data));
    ctx_t c;
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, g_tx, n, 1), TX_STREAM_FINISHED);
    assert_true(c.tx.has_data);
}

static void test_reject_noncanonical_long_form(void **state) {
    (void) state;
    ctx_t c;
    // data of 16 bytes encoded with the long form 0xb8 0x10 instead of 0x90
    size_t n = build_simple(g_tx, sizeof(g_tx), NULL, 0);
    size_t data_off = n - 1 - 4 - 1 - 1;  // extra_params, descriptor(4), access_list, data
    assert_int_equal(g_tx[data_off], 0x80);
    memmove(g_tx + data_off + 2 + 16, g_tx + data_off + 1, n - data_off - 1);
    g_tx[data_off] = 0xb8;
    g_tx[data_off + 1] = 0x10;
    memset(g_tx + data_off + 2, 0xaa, 16);
    g_tx[2] += 17;  // list payload grows by 2 header + 16 data - 1 old header
    assert_rejected_all_chunk_sizes(g_tx, n + 17);

    // the same 16 bytes in short form are accepted
    uint8_t data[16];
    memset(data, 0xaa, sizeof(data));
    n = build_simple(g_tx, sizeof(g_tx), data, sizeof(data));
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, g_tx, n, 1), TX_STREAM_FINISHED);

    // leading zero in the length bytes: 0xb9 0x00 0x40 for 64 bytes
    uint8_t data64[64];
    memset(data64, 0xbb, sizeof(data64));
    n = build_simple(g_tx, sizeof(g_tx), data64, sizeof(data64));
    data_off = n - 64 - 1 - 4 - 1 - 2;  // data payload, extra, descriptor, access, b8 40
    assert_int_equal(g_tx[data_off], 0xb8);
    assert_int_equal(g_tx[data_off + 1], 0x40);
    memmove(g_tx + data_off + 3, g_tx + data_off + 2, n - data_off - 2);
    g_tx[data_off] = 0xb9;
    g_tx[data_off + 1] = 0x00;
    g_tx[data_off + 2] = 0x40;
    g_tx[2] += 1;
    assert_rejected_all_chunk_sizes(g_tx, n + 1);
}

static void test_reject_bad_descriptor(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    // descriptor bytes are the 3 bytes before the final empty extra_params
    buf[n - 2] = 0x01;  // 01 00 01
    assert_rejected_all_chunk_sizes(buf, n);
}

static void test_reject_nonempty_extra_params(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    buf[n - 1] = 0x01;  // extra_params = single byte 0x01
    assert_rejected_all_chunk_sizes(buf, n);
}

static void test_reject_wrong_type_byte(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    ctx_t c;
    buf[0] = 0x01;
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, n, 255), TX_STREAM_ERROR);
}

// Regression carried over from the buffered parser: an 8-byte RLP length
// field used to overflow the bounds arithmetic. The streaming parser rejects
// any length-of-length above 4 bytes straight from the prefix.
static void test_reject_length_of_length_overflow(void **state) {
    (void) state;
    uint8_t buf[64];
    ctx_t c;
    memset(buf, 0xff, sizeof(buf));
    buf[0] = 0x02;
    buf[1] = 0xf8;  // list, 1 length byte
    buf[2] = 0x3b;  // payload claims 59 bytes
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, sizeof(buf), 255), TX_STREAM_ERROR);

    // same for a long string header on a field: 0xbc = 5 length bytes
    size_t n = build_simple(g_tx, sizeof(g_tx), NULL, 0);
    size_t data_off = n - 1 - 4 - 1 - 1;
    assert_int_equal(g_tx[data_off], 0x80);
    g_tx[data_off] = 0xbc;
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, g_tx, n, 255), TX_STREAM_ERROR);
}

static void test_truncated_is_processing_not_finished(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    ctx_t c;
    for (size_t cut = 1; cut < n; cut += 3) {
        tx_stream_init(&c.s, &c.tx);
        assert_int_equal(feed_chunked(&c, buf, n - cut, 255), TX_STREAM_PROCESSING);
        // the parser is still waiting, so the rest of the bytes complete it
        assert_int_equal(feed_chunked(&c, buf + (n - cut), cut, 255), TX_STREAM_FINISHED);
    }
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(tx_stream_feed(&c.s, &c.tx, buf, 0), TX_STREAM_PROCESSING);
}

static void test_reject_trailing_bytes(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    ctx_t c;
    uint8_t extra = 0x00;

    // trailing byte in the same chunk
    buf[n] = extra;
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, n + 1, 4096), TX_STREAM_ERROR);

    // trailing byte in a later call, after FINISHED was already reported
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, n, 255), TX_STREAM_FINISHED);
    assert_int_equal(tx_stream_feed(&c.s, &c.tx, &extra, 1), TX_STREAM_ERROR);

    // an empty call after FINISHED is harmless
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, n, 255), TX_STREAM_FINISHED);
    assert_int_equal(tx_stream_feed(&c.s, &c.tx, buf, 0), TX_STREAM_FINISHED);
}

static void test_reject_list_length_mismatch(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    ctx_t c;
    // 02 f8 65 ... : buf[2] is the list payload length
    assert_int_equal(buf[1], 0xf8);

    buf[2] = 0x64;  // list claims one byte less than the fields need
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, n, 255), TX_STREAM_ERROR);

    buf[2] = 0x66;  // list claims one byte more: extra_params is not the last field
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, n, 255), TX_STREAM_ERROR);

    buf[2] = 0x00;  // long form with a length below 56 is non-canonical
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, n, 255), TX_STREAM_ERROR);

    buf[1] = 0xc0;  // empty outer list in short form
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, n, 255), TX_STREAM_ERROR);
}

static void test_reject_string_where_list_expected(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    // outer list header replaced by a string header of the same length
    buf[1] = 0xb8;
    assert_rejected_all_chunk_sizes(buf, n);

    // access_list (0xc0 before descriptor) replaced by an empty string
    n = unhex(VALID_64B_TO, buf, sizeof(buf));
    assert_int_equal(buf[n - 6], 0xc0);
    buf[n - 6] = 0x80;
    assert_rejected_all_chunk_sizes(buf, n);

    // data (0x80 before access_list) replaced by an empty list
    n = unhex(VALID_64B_TO, buf, sizeof(buf));
    assert_int_equal(buf[n - 7], 0x80);
    buf[n - 7] = 0xc0;
    assert_rejected_all_chunk_sizes(buf, n);
}

static void test_large_data_sets_flag_only(void **state) {
    (void) state;
    const size_t data_len = 3000;  // far above the old 510 byte buffer
    ctx_t c;
    for (size_t i = 0; i < data_len; i++) {
        g_data[i] = (uint8_t) (i * 7 + 3);
    }
    size_t n = build_simple(g_tx, sizeof(g_tx), g_data, data_len);
    assert_true(n > data_len);

    for (size_t ci = 0; ci < N_CHUNK_SIZES; ci++) {
        tx_stream_init(&c.s, &c.tx);
        assert_int_equal(feed_chunked(&c, g_tx, n, CHUNK_SIZES[ci]), TX_STREAM_FINISHED);
        assert_true(c.tx.has_data);
        assert_false(c.tx.has_access_list);
        assert_memory_equal(c.tx.to, TO_64B, 64);
        // the fields after `data` are still decoded correctly
        assert_int_equal(c.tx.descriptor_len, 3);
        assert_int_equal(c.s.total_len, n);
    }
}

static void test_nonempty_access_list_sets_flag(void **state) {
    (void) state;
    // access_list = [ [ to, [] ] ] encoded by hand: c3 c2 80 c0
    static const uint8_t access_list[] = {0xc3, 0xc2, 0x80, 0xc0};
    ctx_t c;
    size_t n = build_tx(g_tx,
                        sizeof(g_tx),
                        TO_64B,
                        64,
                        VALUE_0_01,
                        sizeof(VALUE_0_01),
                        NULL,
                        0,
                        access_list,
                        sizeof(access_list));
    for (size_t ci = 0; ci < N_CHUNK_SIZES; ci++) {
        tx_stream_init(&c.s, &c.tx);
        assert_int_equal(feed_chunked(&c, g_tx, n, CHUNK_SIZES[ci]), TX_STREAM_FINISHED);
        assert_false(c.tx.has_data);
        assert_true(c.tx.has_access_list);
        assert_int_equal(c.tx.descriptor_len, 3);
    }

    // a large access_list is skipped without being stored
    static uint8_t big[700];
    size_t h = 0;
    big[h++] = 0xf9;
    big[h++] = (uint8_t) (600 >> 8);
    big[h++] = (uint8_t) (600 & 0xff);
    memset(big + h, 0x80, 600);  // 600 empty strings
    n = build_tx(g_tx, sizeof(g_tx), TO_64B, 64, VALUE_0_01, 7, NULL, 0, big, h + 600);
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, g_tx, n, 255), TX_STREAM_FINISHED);
    assert_true(c.tx.has_access_list);
}

static void test_short_data(void **state) {
    (void) state;
    const uint8_t data[3] = {0xaa, 0xbb, 0xcc};
    ctx_t c;
    size_t n = build_simple(g_tx, sizeof(g_tx), data, sizeof(data));
    for (size_t ci = 0; ci < N_CHUNK_SIZES; ci++) {
        tx_stream_init(&c.s, &c.tx);
        assert_int_equal(feed_chunked(&c, g_tx, n, CHUNK_SIZES[ci]), TX_STREAM_FINISHED);
        assert_true(c.tx.has_data);
    }

    // a single byte <= 0x7f is RLP encoded as itself (no header)
    const uint8_t one[1] = {0x05};
    n = build_simple(g_tx, sizeof(g_tx), one, 1);
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, g_tx, n, 1), TX_STREAM_FINISHED);
    assert_true(c.tx.has_data);
}

static void test_empty_value_field(void **state) {
    (void) state;
    ctx_t c;
    size_t n = build_tx(g_tx, sizeof(g_tx), TO_64B, 64, NULL, 0, NULL, 0, NULL, 0);
    for (size_t ci = 0; ci < N_CHUNK_SIZES; ci++) {
        tx_stream_init(&c.s, &c.tx);
        assert_int_equal(feed_chunked(&c, g_tx, n, CHUNK_SIZES[ci]), TX_STREAM_FINISHED);
        assert_int_equal(c.tx.value_len, 0);
        assert_memory_equal(c.tx.to, TO_64B, 64);
    }
}

static void test_reject_oversized_value(void **state) {
    (void) state;
    uint8_t value[33];
    ctx_t c;
    memset(value, 0x11, sizeof(value));
    size_t n = build_tx(g_tx, sizeof(g_tx), TO_64B, 64, value, sizeof(value), NULL, 0, NULL, 0);
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, g_tx, n, 255), TX_STREAM_ERROR);

    // 32 bytes is the maximum and is accepted
    n = build_tx(g_tx, sizeof(g_tx), TO_64B, 64, value, 32, NULL, 0, NULL, 0);
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, g_tx, n, 255), TX_STREAM_FINISHED);
    assert_int_equal(c.tx.value_len, 32);
}

static void test_error_is_sticky(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    ctx_t c;
    tx_stream_init(&c.s, &c.tx);
    buf[0] = 0x01;
    assert_int_equal(tx_stream_feed(&c.s, &c.tx, buf, 1), TX_STREAM_ERROR);
    buf[0] = 0x02;
    // valid bytes after an error are still rejected until re-init
    assert_int_equal(feed_chunked(&c, buf, n, 255), TX_STREAM_ERROR);
    assert_int_equal(tx_stream_feed(&c.s, &c.tx, buf, 0), TX_STREAM_ERROR);
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, buf, n, 255), TX_STREAM_FINISHED);
}

static void test_init_resets_state(void **state) {
    (void) state;
    ctx_t c;
    memset(&c, 0xee, sizeof(c));
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(c.s.field, TX_F_TYPE);
    assert_false(c.s.in_payload);
    assert_false(c.s.failed);
    assert_int_equal(c.s.total_len, 0);
    assert_int_equal(c.tx.to[0], 0);
    assert_false(c.tx.has_data);
    assert_false(c.tx.has_access_list);
}

static void test_reject_total_length_cap(void **state) {
    (void) state;
    const size_t data_len = TX_MAX_TOTAL_LEN + 1000;
    ctx_t c;
    memset(g_data, 0x5a, data_len);
    size_t n = build_simple(g_tx, sizeof(g_tx), g_data, data_len);
    assert_true(n > TX_MAX_TOTAL_LEN);
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(feed_chunked(&c, g_tx, n, 255), TX_STREAM_ERROR);
    assert_true(c.s.total_len <= TX_MAX_TOTAL_LEN);
}

static void test_null_arguments(void **state) {
    (void) state;
    uint8_t buf[600];
    size_t n = unhex(VALID_64B_TO, buf, sizeof(buf));
    ctx_t c;
    assert_int_equal(tx_stream_feed(NULL, &c.tx, buf, n), TX_STREAM_ERROR);
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(tx_stream_feed(&c.s, NULL, buf, n), TX_STREAM_ERROR);
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(tx_stream_feed(&c.s, &c.tx, NULL, n), TX_STREAM_ERROR);
    // NULL with zero length is a no-op
    tx_stream_init(&c.s, &c.tx);
    assert_int_equal(tx_stream_feed(&c.s, &c.tx, NULL, 0), TX_STREAM_PROCESSING);
    // init tolerates NULL outputs
    tx_stream_init(NULL, NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_builder_matches_reference_vectors),
        cmocka_unit_test(test_valid_64byte_recipient_all_chunk_sizes),
        cmocka_unit_test(test_contract_creation),
        cmocka_unit_test(test_reject_20byte_recipient),
        cmocka_unit_test(test_reject_legacy_10_fields),
        cmocka_unit_test(test_reject_oversized_nonce),
        cmocka_unit_test(test_reject_noncanonical_single_byte),
        cmocka_unit_test(test_reject_leading_zero_in_integer),
        cmocka_unit_test(test_reject_noncanonical_long_form),
        cmocka_unit_test(test_reject_bad_descriptor),
        cmocka_unit_test(test_reject_nonempty_extra_params),
        cmocka_unit_test(test_reject_wrong_type_byte),
        cmocka_unit_test(test_reject_length_of_length_overflow),
        cmocka_unit_test(test_truncated_is_processing_not_finished),
        cmocka_unit_test(test_reject_trailing_bytes),
        cmocka_unit_test(test_reject_list_length_mismatch),
        cmocka_unit_test(test_reject_string_where_list_expected),
        cmocka_unit_test(test_large_data_sets_flag_only),
        cmocka_unit_test(test_nonempty_access_list_sets_flag),
        cmocka_unit_test(test_short_data),
        cmocka_unit_test(test_empty_value_field),
        cmocka_unit_test(test_reject_oversized_value),
        cmocka_unit_test(test_error_is_sticky),
        cmocka_unit_test(test_init_resets_state),
        cmocka_unit_test(test_reject_total_length_cap),
        cmocka_unit_test(test_null_arguments),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
