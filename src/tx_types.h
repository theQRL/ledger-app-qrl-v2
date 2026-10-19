#pragma once

/*
 * Transaction-level types shared by the RLP parsers, the UI and the APDU
 * handlers.
 *
 * This header deliberately depends on nothing from the Ledger SDK so that the
 * parsers can be compiled and unit-tested on the host (see unit-tests/).
 */

#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t

#define ADDRESS_LENGTH 64
#define MAX_FIELD_SIZE 32

/**
 * Decoded fields of a QRL v2.0 type-2 transaction (sighash preimage).
 */
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

/*
 * Streaming parser state (tx_stream.c).
 */

/** Longest RLP item header: 1 prefix byte + up to 4 length bytes. */
#define TX_RLP_HDR_MAX 5
/** Sanity cap on the total serialized transaction size accepted from the host. */
#define TX_MAX_TOTAL_LEN 65536u

typedef enum {
    TX_F_TYPE = 0,  /// leading 0x02 byte, not RLP encoded
    TX_F_LIST,      /// header of the outer list
    TX_F_CHAIN_ID,
    TX_F_NONCE,
    TX_F_GAS_TIP_CAP,
    TX_F_GAS_FEE_CAP,
    TX_F_GAS,
    TX_F_TO,
    TX_F_VALUE,
    TX_F_DATA,
    TX_F_ACCESS_LIST,
    TX_F_DESCRIPTOR,
    TX_F_EXTRA_PARAMS,
    TX_F_DONE
} tx_field_e;

typedef enum {
    TX_STREAM_PROCESSING = 0,  /// more bytes are needed
    TX_STREAM_FINISHED,        /// outer list closed, transaction fully decoded
    TX_STREAM_ERROR            /// malformed input, the state is sticky
} tx_stream_status_e;

typedef struct {
    tx_field_e field;             /// field currently being received
    bool in_payload;              /// false: collecting the RLP header, true: consuming payload
    bool failed;                  /// set on the first error, never cleared
    uint8_t hdr[TX_RLP_HDR_MAX];  /// RLP header bytes collected so far
    uint8_t hdr_len;              /// number of valid bytes in `hdr`
    uint8_t hdr_need;             /// total header length once the prefix is known, 0 otherwise
    uint32_t field_len;           /// payload length of the current field
    uint32_t field_pos;           /// payload bytes consumed so far
    uint32_t list_remaining;      /// outer list payload bytes still expected
    uint32_t total_len;           /// bytes fed so far, checked against TX_MAX_TOTAL_LEN
} tx_stream_t;
