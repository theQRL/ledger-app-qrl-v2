/* Tests for the address checksum and BIP-32 path validation.
 *
 * The checksum is the user's tamper-detection mechanism: it is what makes a
 * substituted recipient address visible on screen, so a silent change to the
 * casing rule would be a security regression. Expected values were generated
 * independently in Python (SHAKE-256 over the 128-char lowercase hex body,
 * uppercasing a-f where the corresponding nibble is >= 8, 'Q' not hashed).
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "address_format.h"

#define CHECKSUM_ALL_AB                                                                  \
    "QabaBABabaBAbAbAbABaBABaBabaBabaBAbabaBABABAbAbabababAbaBaBABABabABaBaBABABaBabaBA" \
    "BaBabABAbABabaBAbABAbABAbaBabABababAbaBaBabaBAB"

#define CHECKSUM_COUNTER                                                                 \
    "Q000102030405060708090a0B0C0D0e0f101112131415161718191A1B1C1D1e1F202122232425262728" \
    "292a2B2c2d2E2f303132333435363738393A3B3C3d3e3f"

static void test_checksum_known_answers(void **state) {
    (void) state;
    char out[1 + 2 * ADDRESS_SIZE + 1];

    uint8_t all_ab[ADDRESS_SIZE];
    memset(all_ab, 0xab, sizeof(all_ab));
    assert_true(format_checksummed_address(all_ab, out, sizeof(out)));
    assert_string_equal(out, CHECKSUM_ALL_AB);

    uint8_t counter[ADDRESS_SIZE];
    for (int i = 0; i < ADDRESS_SIZE; i++) counter[i] = (uint8_t) i;
    assert_true(format_checksummed_address(counter, out, sizeof(out)));
    assert_string_equal(out, CHECKSUM_COUNTER);
}

static void test_checksum_shape(void **state) {
    (void) state;
    char out[1 + 2 * ADDRESS_SIZE + 1];
    uint8_t addr[ADDRESS_SIZE];
    memset(addr, 0xab, sizeof(addr));

    assert_true(format_checksummed_address(addr, out, sizeof(out)));
    assert_int_equal(strlen(out), 1 + 2 * ADDRESS_SIZE);
    assert_int_equal(out[0], 'Q');
    /* Digits are never re-cased; only a-f/A-F may differ. */
    for (size_t i = 1; i < strlen(out); i++) {
        char c = out[i];
        assert_true((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    }
}

static void test_checksum_is_sensitive_to_input(void **state) {
    (void) state;
    char a[1 + 2 * ADDRESS_SIZE + 1], b[1 + 2 * ADDRESS_SIZE + 1];
    uint8_t addr[ADDRESS_SIZE];

    memset(addr, 0xab, sizeof(addr));
    assert_true(format_checksummed_address(addr, a, sizeof(a)));
    addr[ADDRESS_SIZE - 1] ^= 0x01; /* flip one bit of the last byte */
    assert_true(format_checksummed_address(addr, b, sizeof(b)));
    assert_string_not_equal(a, b);
}

static void test_checksum_rejects_small_buffer(void **state) {
    (void) state;
    char small[1 + 2 * ADDRESS_SIZE]; /* one byte short of the NUL */
    uint8_t addr[ADDRESS_SIZE] = {0};
    assert_false(format_checksummed_address(addr, small, sizeof(small)));
    assert_false(format_checksummed_address(addr, NULL, sizeof(small) + 1));
    assert_false(format_checksummed_address(NULL, small, sizeof(small) + 1));
}

static void test_bip32_path_validation(void **state) {
    (void) state;
    /* m/44'/238'/0'/0/0 */
    uint32_t ok[5] = {0x8000002Cu, 0x800000EEu, 0x80000000u, 0, 0};
    assert_true(is_valid_zond_bip32_path(ok, 5));

    assert_false(is_valid_zond_bip32_path(ok, 4));  /* wrong length */
    assert_false(is_valid_zond_bip32_path(ok, 6));

    uint32_t bad_purpose[5] = {0x8000002Du, 0x800000EEu, 0x80000000u, 0, 0};
    assert_false(is_valid_zond_bip32_path(bad_purpose, 5));

    uint32_t bad_coin[5] = {0x8000002Cu, 0x800000EFu, 0x80000000u, 0, 0};
    assert_false(is_valid_zond_bip32_path(bad_coin, 5));

    uint32_t soft_account[5] = {0x8000002Cu, 0x800000EEu, 0x00000000u, 0, 0};
    assert_false(is_valid_zond_bip32_path(soft_account, 5)); /* account must be hardened */

    uint32_t hard_change[5] = {0x8000002Cu, 0x800000EEu, 0x80000000u, 0x80000000u, 0};
    assert_false(is_valid_zond_bip32_path(hard_change, 5)); /* change must not be */

    uint32_t hard_index[5] = {0x8000002Cu, 0x800000EEu, 0x80000000u, 0, 0x80000000u};
    assert_false(is_valid_zond_bip32_path(hard_index, 5)); /* index must not be */
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_checksum_known_answers),
        cmocka_unit_test(test_checksum_shape),
        cmocka_unit_test(test_checksum_is_sensitive_to_input),
        cmocka_unit_test(test_checksum_rejects_small_buffer),
        cmocka_unit_test(test_bip32_path_validation),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
