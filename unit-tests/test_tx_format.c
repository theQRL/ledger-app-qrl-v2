#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>
#include "tx_format.h"

static void test_decimal_boundaries(void **state) {
    (void) state;
    uint8_t one[] = {0xff}, eight[8], seventeen[17], thirty_two[32];
    memset(eight, 0xff, sizeof(eight));
    memset(seventeen, 0xff, sizeof(seventeen));
    memset(thirty_two, 0xff, sizeof(thirty_two));
    char out[TX_FORMAT_MAX_DECIMAL_DIGITS + 1];
    assert_true(uint8_array_to_decimal(one, sizeof(one), out, sizeof(out)));
    assert_string_equal(out, "255");
    assert_true(uint8_array_to_decimal(eight, sizeof(eight), out, sizeof(out)));
    assert_string_equal(out, "18446744073709551615");
    assert_true(uint8_array_to_decimal(seventeen, sizeof(seventeen), out, sizeof(out)));
    assert_int_equal(strlen(out), 41);
    assert_true(uint8_array_to_decimal(thirty_two, sizeof(thirty_two), out, sizeof(out)));
    assert_string_equal(
        out,
        "115792089237316195423570985008687907853269984665640564039457584007913129639935");
    assert_false(uint8_array_to_decimal(thirty_two, sizeof(thirty_two), out, 78));
}

static void test_qrl_format(void **state) {
    (void) state;
    uint8_t amount[] = {0x23, 0x86, 0xf2, 0x6f, 0xc1, 0x00, 0x00};
    char out[TX_FORMAT_MAX_AMOUNT_LEN];
    assert_true(format_qrl_amount(amount, sizeof(amount), out, sizeof(out)));
    assert_string_equal(out, "0.01");
}

static void test_fee_product(void **state) {
    (void) state;
    uint8_t cap[] = {0x02, 0x54, 0x0b, 0xe4, 0x00}; /* 10 gwei */
    uint8_t gas[] = {0x07, 0xa1, 0x20};             /* 500000 */
    uint8_t product[TX_FORMAT_MAX_INTEGER_BYTES];
    size_t product_len = sizeof(product);
    char out[TX_FORMAT_MAX_AMOUNT_LEN];
    assert_true(multiply_uint8_arrays(cap, sizeof(cap), gas, sizeof(gas), product, &product_len));
    assert_true(format_qrl_amount(product, product_len, out, sizeof(out)));
    assert_string_equal(out, "0.005");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_decimal_boundaries),
        cmocka_unit_test(test_qrl_format),
        cmocka_unit_test(test_fee_product),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
