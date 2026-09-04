#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include "constant.h"
#include "address_format.h"

cx_err_t address_from_bip32_path(const uint32_t bip32_path[],
                                 size_t bip32_path_len,
                                 uint8_t address[ADDRESS_SIZE]);
