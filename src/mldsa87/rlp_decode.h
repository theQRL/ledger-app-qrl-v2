#ifndef RLP_DECODE_H
#define RLP_DECODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define ADDRESS_LENGTH 64
#define MAX_FIELD_SIZE 32

typedef struct {
    uint8_t chain_id[MAX_FIELD_SIZE];
    uint8_t chain_id_len;

    uint8_t nonce[8];
    uint8_t nonce_len;

    uint8_t gas_tip_cap[MAX_FIELD_SIZE];
    uint8_t gas_tip_cap_len;

    uint8_t gas_fee_cap[MAX_FIELD_SIZE];
    uint8_t gas_fee_cap_len;

    uint8_t gas[8];
    uint8_t gas_len;

    uint8_t to[ADDRESS_LENGTH];

    uint8_t value[MAX_FIELD_SIZE];
    uint8_t value_len;

    bool has_data;
    bool has_access_list;

    uint8_t descriptor[3];
    uint8_t descriptor_len;
} zond_tx_t;

int decode_ledger_tx(const uint8_t *rlp, size_t rlp_len, zond_tx_t *tx);

#endif
