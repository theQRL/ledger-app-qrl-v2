/* SDK-free half of address.c: path validation and checksummed formatting.
 * Kept in its own translation unit so it can be unit-tested off-device — it
 * needs only SHAKE-256, no BOLOS syscalls. */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "address_format.h"
#include "constant.h"
#include "shake256.h"

bool is_valid_zond_bip32_path(const uint32_t bip32_path[], size_t bip32_path_len) {
    if (bip32_path_len != 5) {
        return false;
    }
    if (bip32_path[0] != 0x8000002Cu ||  // purpose 44'
        bip32_path[1] != 0x800000EEu ||  // coin type 238'
        (bip32_path[2] & 0x80000000u) == 0 || (bip32_path[3] & 0x80000000u) != 0 ||
        (bip32_path[4] & 0x80000000u) != 0) {
        return false;
    }
    return true;
}

// EIP-55-style checksum casing with SHAKE-256 over the 128-char lowercase hex
// body (the 'Q' prefix is not hashed). out must hold 1 + 2*ADDRESS_SIZE + 1.
bool format_checksummed_address(const uint8_t address[ADDRESS_SIZE], char *out, size_t out_len) {
    static const char hexc[] = "0123456789abcdef";

    if (address == NULL || out == NULL || out_len < 1 + 2 * ADDRESS_SIZE + 1) {
        return false;
    }

    char *body = out + 1;
    for (int i = 0; i < ADDRESS_SIZE; i++) {
        body[2 * i] = hexc[address[i] >> 4];
        body[2 * i + 1] = hexc[address[i] & 0x0f];
    }

    uint8_t mask[ADDRESS_SIZE] = {0};
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, (const uint8_t *) body, 2 * ADDRESS_SIZE);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, mask, ADDRESS_SIZE);
    shake256_clear(&ctx);

    for (int i = 0; i < 2 * ADDRESS_SIZE; i++) {
        uint8_t nibble = (i % 2 == 0) ? (mask[i / 2] >> 4) : (mask[i / 2] & 0x0f);
        if (body[i] >= 'a' && body[i] <= 'f' && nibble >= 8) {
            body[i] -= 'a' - 'A';
        }
    }

    out[0] = 'Q';
    out[1 + 2 * ADDRESS_SIZE] = '\0';
    return true;
}
