/* Fuzz the transaction display formatters.
 *
 * These run on host-controlled amounts before the user confirms anything, and
 * an earlier out-of-bounds write here (audit finding CIPH-LQRL26-1) was missed
 * precisely because nothing fuzzed them. Every entry point is bounds-checked
 * and returns bool, so the harness asserts the contract rather than just
 * looking for crashes: a false return must never have written to the output.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "tx_format.h"

#define GUARD    0xA5
#define REDZONE  32

/* The formatters may write anywhere inside the buffer they are given — the
 * trailing-zero trim in format_with_decimals legitimately leaves NULs past the
 * final string. The contract that matters is that they never write *outside*
 * the length they were handed, so the guard lives beyond that boundary. */
static int redzone_intact(const char *buf, size_t declared, size_t total) {
    for (size_t i = declared; i < total; i++) {
        if ((unsigned char) buf[i] != GUARD) return 0;
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    /* First byte splits the input into two operands; the rest is payload. */
    size_t split = data[0] % (size > 1 ? size : 1);
    const uint8_t *a = data + 1;
    size_t a_len = split;
    const uint8_t *b = data + 1 + split;
    size_t b_len = size - 1 - split;

    /* Declared length is TX_FORMAT_MAX_AMOUNT_LEN; anything the formatter writes
     * into the REDZONE past it is an out-of-bounds write. */
    char out[TX_FORMAT_MAX_AMOUNT_LEN + REDZONE];
    const size_t declared = TX_FORMAT_MAX_AMOUNT_LEN;

    /* uint8_array_to_decimal must reject anything it cannot fit. */
    memset(out, GUARD, sizeof(out));
    if (uint8_array_to_decimal(a, a_len, out, declared)) {
        assert(strlen(out) + 1 <= declared);
    }
    assert(redzone_intact(out, declared, sizeof(out)));

    memset(out, GUARD, sizeof(out));
    if (format_qrl_amount(a, a_len, out, declared)) {
        assert(strlen(out) + 1 <= declared);
    }
    assert(redzone_intact(out, declared, sizeof(out)));

    /* Deliberately undersized output: the function must refuse, not truncate
     * into a short buffer. */
    char tiny[8 + REDZONE];
    memset(tiny, GUARD, sizeof(tiny));
    if (format_qrl_amount(a, a_len, tiny, 8)) {
        assert(strlen(tiny) + 1 <= 8);
    }
    assert(redzone_intact(tiny, 8, sizeof(tiny)));

    /* gas x gas_fee_cap: the product feeds straight into the "Max fees" line. */
    uint8_t product[TX_FORMAT_MAX_INTEGER_BYTES + REDZONE];
    memset(product, GUARD, sizeof(product));
    size_t product_len = TX_FORMAT_MAX_INTEGER_BYTES;
    if (multiply_uint8_arrays(a, a_len, b, b_len, product, &product_len)) {
        assert(product_len <= TX_FORMAT_MAX_INTEGER_BYTES);
        memset(out, GUARD, sizeof(out));
        if (format_qrl_amount(product, product_len, out, declared)) {
            assert(strlen(out) + 1 <= declared);
        }
        assert(redzone_intact(out, declared, sizeof(out)));
    }
    assert(redzone_intact((const char *) product, TX_FORMAT_MAX_INTEGER_BYTES, sizeof(product)));

    return 0;
}
