#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

#include "constant.h"

/**
 * Format a 64-byte address as "Q" + 128 hex chars with EIP-55-style
 * SHAKE-256 checksum casing. out must hold 1 + 2*ADDRESS_SIZE + 1 bytes.
 *
 * @return true if success, false otherwise.
 */
bool format_checksummed_address(const uint8_t address[ADDRESS_SIZE], char *out, size_t out_len);

/**
 * Check that a BIP32 path is the canonical Zond path:
 * m/44'/238'/account'/change/index with non-hardened change and index.
 *
 * @return true if the path is valid, false otherwise.
 */
bool is_valid_zond_bip32_path(const uint32_t bip32_path[], size_t bip32_path_len);
