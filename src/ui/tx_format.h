#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TX_FORMAT_MAX_INTEGER_BYTES  40
#define TX_FORMAT_MAX_DECIMAL_DIGITS 97
#define TX_FORMAT_MAX_AMOUNT_LEN     100

bool uint8_array_to_decimal(const uint8_t *, size_t, char *, size_t);
bool format_with_decimals(const char *, size_t, char *, size_t);
bool format_qrl_amount(const uint8_t *, size_t, char *, size_t);
bool multiply_uint8_arrays(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t *);
