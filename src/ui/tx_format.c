#include "tx_format.h"
#include <string.h>

bool uint8_array_to_decimal(const uint8_t *bytes, size_t len, char *out, size_t out_len) {
    uint8_t temp[TX_FORMAT_MAX_INTEGER_BYTES] = {0};
    char result[TX_FORMAT_MAX_DECIMAL_DIGITS + 1];
    size_t index = sizeof(result) - 1;
    if (!bytes || !out || out_len == 0 || len > sizeof(temp)) return false;
    if (len) memcpy(temp, bytes, len);
    result[index] = '\0';
    do {
        unsigned int remainder = 0;
        bool zero = true;
        for (size_t i = 0; i < len; i++) {
            unsigned int val = (remainder << 8) | temp[i];
            temp[i] = (uint8_t) (val / 10);
            remainder = val % 10;
            zero &= temp[i] == 0;
        }
        if (index == 0) return false;
        result[--index] = (char) ('0' + remainder);
        if (zero) break;
    } while (true);
    size_t bytes_needed = sizeof(result) - index;
    if (bytes_needed > out_len) return false;
    memcpy(out, result + index, bytes_needed);
    return true;
}

bool format_with_decimals(const char *raw, size_t decimals, char *out, size_t out_len) {
    if (!raw || !out || out_len == 0) return false;
    size_t len = strlen(raw), pos = 0;
    if (decimals == 0) {
        if (len + 1 > out_len) return false;
        memcpy(out, raw, len + 1);
        return true;
    }
    size_t leading = len < decimals ? decimals - len : 0;
    size_t needed =
        (len > decimals ? len - decimals : 1) + 1 + leading + (len > decimals ? decimals : len) + 1;
    if (needed > out_len) return false;
    if (len <= decimals) {
        out[pos++] = '0';
        out[pos++] = '.';
        memset(out + pos, '0', leading);
        pos += leading;
        memcpy(out + pos, raw, len);
        pos += len;
    } else {
        size_t integer_len = len - decimals;
        memcpy(out + pos, raw, integer_len);
        pos += integer_len;
        out[pos++] = '.';
        memcpy(out + pos, raw + integer_len, decimals);
        pos += decimals;
    }
    out[pos] = '\0';
    while (pos && out[pos - 1] == '0') out[--pos] = '\0';
    if (pos && out[pos - 1] == '.') out[--pos] = '\0';
    return true;
}

bool format_qrl_amount(const uint8_t *amount, size_t len, char *out, size_t out_len) {
    char decimal[TX_FORMAT_MAX_DECIMAL_DIGITS + 1];
    return uint8_array_to_decimal(amount, len, decimal, sizeof(decimal)) &&
           format_with_decimals(decimal, 18, out, out_len);
}

bool multiply_uint8_arrays(const uint8_t *a,
                           size_t a_len,
                           const uint8_t *b,
                           size_t b_len,
                           uint8_t *out,
                           size_t *out_len) {
    uint32_t accum[TX_FORMAT_MAX_INTEGER_BYTES] = {0};
    if (!a || !b || !out || !out_len || a_len + b_len > TX_FORMAT_MAX_INTEGER_BYTES) return false;
    size_t full_len = a_len + b_len;
    if (!full_len) {
        if (*out_len < 1) return false;
        out[0] = 0;
        *out_len = 1;
        return true;
    }
    for (size_t i = 0; i < a_len; i++)
        for (size_t j = 0; j < b_len; j++)
            accum[full_len - 1 - i - j] += (uint32_t) a[a_len - 1 - i] * b[b_len - 1 - j];
    for (size_t i = full_len - 1; i > 0; i--) {
        accum[i - 1] += accum[i] >> 8;
        accum[i] &= 0xff;
    }
    size_t first = 0;
    while (first + 1 < full_len && accum[first] == 0) first++;
    size_t significant = full_len - first;
    if (significant > *out_len) return false;
    for (size_t i = 0; i < significant; i++) out[i] = (uint8_t) accum[first + i];
    *out_len = significant;
    return true;
}
