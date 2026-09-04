#include "rlp_decode.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cx.h"

static int parse_rlp_item(const uint8_t *input,
                          size_t input_len,
                          const uint8_t **out_data,
                          size_t *out_len) {
    if (input_len == 0) {
        PRINTF("ERROR input len\n");
        return -1;
    }

    uint8_t prefix = input[0];

    if (prefix <= 0x7f) {
        // single byte
        *out_data = &input[0];
        *out_len = 1;
        return 1;
    } else if (prefix <= 0xb7) {
        // short string: 0x80 + len
        size_t len = prefix - 0x80;
        if (len > input_len - 1) {
            PRINTF("ERROR short string\n");
            return -1;
        }
        if (len == 1 && input[1] < 0x80) return -1;
        *out_data = &input[1];
        *out_len = len;
        return 1 + len;
    } else if (prefix <= 0xbf) {
        // long string: 0xb7 + len_of_len
        size_t len_of_len = prefix - 0xb7;
        if (len_of_len > input_len - 1) {
            PRINTF("ERROR long string\n");
            return -1;
        }
        size_t len = 0;
        if (input[1] == 0) return -1;
        for (size_t i = 0; i < len_of_len; i++) {
            len = (len << 8) | input[1 + i];
        }
        if (len > input_len - 1 - len_of_len) {
            PRINTF("ERROR long string 2\n");
            return -1;
        }
        if (len < 56) return -1;
        *out_data = &input[1 + len_of_len];
        *out_len = len;
        return 1 + len_of_len + len;
    } else if (prefix <= 0xf7) {
        // Short list
        size_t len = prefix - 0xc0;
        if (1 + len > input_len) return -1;
        *out_data = &input[1];
        *out_len = len;
        return 1 + len;
    } else {
        // Long list
        size_t len_of_len = prefix - 0xf7;
        if (len_of_len > input_len - 1) return -1;
        size_t len = 0;
        if (input[1] == 0) return -1;
        for (size_t i = 0; i < len_of_len; i++) {
            len = (len << 8) | input[1 + i];
        }
        // subtractive form: the additive check overflows for huge len
        if (len > input_len - 1 - len_of_len) return -1;
        if (len < 56) return -1;
        *out_data = &input[1 + len_of_len];
        *out_len = len;
        return 1 + len_of_len + len;
    }
}

static int parse_rlp_list_header(const uint8_t *input,
                                 size_t input_len,
                                 size_t *payload_len,
                                 size_t *header_len) {
    if (input_len == 0) {
        PRINTF("ERROR parse header input len\n");
        return -1;
    }
    uint8_t prefix = input[0];
    if (prefix >= 0xc0 && prefix <= 0xf7) {
        *payload_len = prefix - 0xc0;
        *header_len = 1;
        if (*payload_len > input_len - *header_len) {
            PRINTF("header prefix 0xc0\n");
            return -1;
        }
        return 0;
    } else if (prefix >= 0xf8) {
        size_t len_of_len = prefix - 0xf7;
        if (len_of_len > input_len - 1) {
            PRINTF("header prefix 0xf8\n");
            return -1;
        }
        size_t len = 0;
        if (input[1] == 0) return -1;
        for (size_t i = 0; i < len_of_len; i++) {
            len = (len << 8) | input[1 + i];
        }
        *payload_len = len;
        *header_len = 1 + len_of_len;
        if (*payload_len > input_len - *header_len) {
            PRINTF("header prefix 0xf8 2\n");
            return -1;
        }
        if (len < 56) return -1;
        return 0;
    }
    PRINTF("header else\n");
    return -1;
}

int decode_ledger_tx(const uint8_t *rlp, size_t rlp_len, zond_tx_t *tx) {
    if (rlp_len == 0 || rlp == NULL || tx == NULL) {
        PRINTF("error null\n");
        return -1;
    }

    if (rlp[0] != 0x02) {
        PRINTF("Not a type 2 tx\n");
        return -1;
    }

    const uint8_t *p = rlp + 1;
    size_t remaining = rlp_len - 1;

    size_t list_payload_len = 0;
    size_t list_header_len = 0;
    if (parse_rlp_list_header(p, remaining, &list_payload_len, &list_header_len) != 0) {
        PRINTF("Invalid RLP list header\n");
        return -1;
    }

    PRINTF("header len %d\n", list_header_len);
    PRINTF("payload len %d\n", list_payload_len);

    const uint8_t *payload_start = p + list_header_len;
    const uint8_t *payload_end = payload_start + list_payload_len;

    p += list_header_len;
    remaining -= list_header_len;
    if (list_payload_len > remaining) {
        PRINTF("list_payload_len > remaining\n");
        return -1;
    }

    const uint8_t *val_ptr;
    size_t val_len;
    int consumed;

    // 1. chain_id
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0 || val_len > MAX_FIELD_SIZE || (val_len > 0 && val_ptr[0] == 0)) {
        PRINTF("chain id\n");
        return -1;
    }
    memcpy(tx->chain_id, val_ptr, val_len);
    tx->chain_id_len = val_len;
    p += consumed;
    remaining -= consumed;

    // 2. nonce
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0 || val_len > sizeof(tx->nonce) || (val_len > 0 && val_ptr[0] == 0)) {
        PRINTF("nonce\n");
        return -1;
    }
    memcpy(tx->nonce, val_ptr, val_len);
    tx->nonce_len = val_len;
    p += consumed;
    remaining -= consumed;

    // 3. gas_tip_cap
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0 || val_len > MAX_FIELD_SIZE || (val_len > 0 && val_ptr[0] == 0)) {
        PRINTF("gas tip cap\n");
        return -1;
    }
    memcpy(tx->gas_tip_cap, val_ptr, val_len);
    tx->gas_tip_cap_len = val_len;
    p += consumed;
    remaining -= consumed;

    // 4. gas_fee_cap
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0 || val_len > MAX_FIELD_SIZE || (val_len > 0 && val_ptr[0] == 0)) {
        PRINTF("gas fee cap\n");
        return -1;
    }
    memcpy(tx->gas_fee_cap, val_ptr, val_len);
    tx->gas_fee_cap_len = val_len;
    p += consumed;
    remaining -= consumed;

    // 5. gas
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0 || val_len > sizeof(tx->gas) || (val_len > 0 && val_ptr[0] == 0)) {
        PRINTF("gas\n");
        return -1;
    }
    memcpy(tx->gas, val_ptr, val_len);
    tx->gas_len = val_len;
    p += consumed;
    remaining -= consumed;

    // 6. to
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0 || (val_len != ADDRESS_LENGTH && val_len != 0)) {
        PRINTF("to\n");
        return -1;
    }
    memset(tx->to, 0, ADDRESS_LENGTH);
    if (val_len > 0) memcpy(tx->to, val_ptr, val_len);
    p += consumed;
    remaining -= consumed;

    // 7. value
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0 || val_len > MAX_FIELD_SIZE || (val_len > 0 && val_ptr[0] == 0)) {
        PRINTF("value\n");
        return -1;
    }
    memset(tx->value, 0, MAX_FIELD_SIZE);
    memcpy(tx->value, val_ptr, val_len);  // right-align
    tx->value_len = val_len;
    p += consumed;
    remaining -= consumed;

    // 8. data
    if (remaining == 0 || p[0] >= 0xc0) {
        PRINTF("Data must be an RLP string\n");
        return -1;
    }
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0) {
        PRINTF("Invalid data field\n");
        return -1;
    }
    tx->has_data = val_len != 0;
    p += consumed;
    remaining -= consumed;

    // 9. access_list
    if (remaining == 0 || p[0] < 0xc0) {
        PRINTF("Access list must be an RLP list\n");
        return -1;
    }
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0) {
        PRINTF("Invalid access_list field\n");
        return -1;
    }
    tx->has_access_list = val_len != 0;
    p += consumed;
    remaining -= consumed;

    // 10. descriptor (ML-DSA-87: wallet_type + metadata, exactly 01 00 00)
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0 || val_len != 3 || val_ptr[0] != 0x01 || val_ptr[1] != 0x00 ||
        val_ptr[2] != 0x00) {
        PRINTF("Invalid descriptor field\n");
        return -1;
    }
    memcpy(tx->descriptor, val_ptr, val_len);
    tx->descriptor_len = val_len;
    p += consumed;
    remaining -= consumed;

    // 11. extra_params (reserved by go-qrl, part of the sighash, must be empty)
    consumed = parse_rlp_item(p, remaining, &val_ptr, &val_len);
    if (consumed < 0 || val_len != 0) {
        PRINTF("Invalid extra_params field\n");
        return -1;
    }
    p += consumed;

    if (p != payload_end) {
        PRINTF("Payload length mismatch\n");
        return -1;
    }

    return 0;
}
