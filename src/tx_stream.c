/*****************************************************************************
 *   Streaming RLP parser for QRL v2.0 type-2 transactions.
 *
 *   The serialized transaction arrives in APDU-sized chunks. Instead of
 *   buffering the whole payload, every byte is consumed once and the parser
 *   position is kept in tx_stream_t between calls. Only the fields needed for
 *   validation and display are retained; the caller hashes the raw bytes.
 *****************************************************************************/

#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <string.h>   // memcpy, memset

#include "tx_stream.h"

static tx_stream_status_e stream_fail(tx_stream_t *s) {
    s->failed = true;
    return TX_STREAM_ERROR;
}

void tx_stream_init(tx_stream_t *s, zond_tx_t *tx) {
    if (s != NULL) {
        memset(s, 0, sizeof(*s));
        s->field = TX_F_TYPE;
    }
    if (tx != NULL) {
        memset(tx, 0, sizeof(*tx));
    }
}

/** Integer fields must not carry leading zero bytes (canonical big-endian). */
static bool is_integer_field(tx_field_e f) {
    return f == TX_F_CHAIN_ID || f == TX_F_NONCE || f == TX_F_GAS_TIP_CAP ||
           f == TX_F_GAS_FEE_CAP || f == TX_F_GAS || f == TX_F_VALUE;
}

/**
 * Total header length implied by an RLP prefix byte, or 0 when the length of
 * the length does not fit in TX_RLP_HDR_MAX - 1 bytes.
 */
static uint8_t rlp_header_need(uint8_t prefix) {
    uint8_t len_of_len;

    if (prefix <= 0xb7) {
        return 1;  // single byte (<= 0x7f) or short string
    }
    if (prefix <= 0xbf) {
        len_of_len = prefix - 0xb7;  // long string
    } else if (prefix <= 0xf7) {
        return 1;  // short list
    } else {
        len_of_len = prefix - 0xf7;  // long list
    }
    if (len_of_len > TX_RLP_HDR_MAX - 1) {
        return 0;
    }
    return (uint8_t) (1 + len_of_len);
}

/**
 * Decode a complete RLP header. For a single byte item (prefix <= 0x7f) the
 * prefix itself is the payload and `single` is set with len = 1.
 *
 * Returns false for a non-canonical long form: a leading zero in the length
 * bytes, or a long form used for a payload shorter than 56 bytes.
 */
static bool rlp_header_decode(const uint8_t *hdr,
                              uint8_t hdr_len,
                              bool *is_list,
                              bool *single,
                              uint32_t *len) {
    uint8_t prefix = hdr[0];
    uint32_t l = 0;

    *is_list = false;
    *single = false;

    if (prefix <= 0x7f) {
        *single = true;
        *len = 1;
        return true;
    }
    if (prefix <= 0xb7) {
        *len = prefix - 0x80;
        return true;
    }
    if (prefix >= 0xc0) {
        *is_list = true;
        if (prefix <= 0xf7) {
            *len = prefix - 0xc0;
            return true;
        }
    }
    // long form: hdr[1 .. hdr_len) holds the big-endian payload length
    if (hdr[1] == 0) {
        return false;
    }
    for (uint8_t i = 1; i < hdr_len; i++) {
        l = (l << 8) | hdr[i];
    }
    if (l < 56) {
        return false;
    }
    *len = l;
    return true;
}

/**
 * Validate the header of the field about to be received and switch the
 * parser to payload mode (per-field rules: doc/TRANSACTION.md).
 */
static bool field_begin(tx_stream_t *s, zond_tx_t *tx, bool is_list, uint32_t len) {
    switch (s->field) {
        case TX_F_CHAIN_ID:
        case TX_F_GAS_TIP_CAP:
        case TX_F_GAS_FEE_CAP:
        case TX_F_VALUE:
            if (is_list || len > MAX_FIELD_SIZE) {
                return false;
            }
            break;
        case TX_F_NONCE:
            if (is_list || len > sizeof(tx->nonce)) {
                return false;
            }
            break;
        case TX_F_GAS:
            if (is_list || len > sizeof(tx->gas)) {
                return false;
            }
            break;
        case TX_F_TO:
            if (is_list || (len != 0 && len != ADDRESS_LENGTH)) {
                return false;
            }
            break;
        case TX_F_DATA:
            if (is_list) {
                return false;
            }
            tx->has_data = (len != 0);
            break;
        case TX_F_ACCESS_LIST:
            if (!is_list) {
                return false;
            }
            tx->has_access_list = (len != 0);
            break;
        case TX_F_DESCRIPTOR:
            if (is_list || len != sizeof(tx->descriptor)) {
                return false;
            }
            break;
        case TX_F_EXTRA_PARAMS:
            if (is_list || len != 0) {
                return false;
            }
            break;
        default:
            return false;
    }
    s->field_len = len;
    s->field_pos = 0;
    s->in_payload = true;
    return true;
}

/**
 * Store `n` payload bytes of the current field starting at offset s->field_pos.
 * Bounds were established by field_begin(), so no further checks are needed
 * for the fixed-size fields. The first payload byte carries the canonical
 * encoding checks that need to look at the content.
 */
static bool field_store(const tx_stream_t *s, zond_tx_t *tx, const uint8_t *src, uint32_t n) {
    uint32_t pos = s->field_pos;

    if (pos == 0 && n > 0) {
        // a lone byte below 0x80 must be encoded as itself, not as 0x81 xx
        if (s->hdr[0] == 0x81 && src[0] < 0x80) {
            return false;
        }
        if (is_integer_field(s->field) && src[0] == 0) {
            return false;
        }
    }

    switch (s->field) {
        case TX_F_CHAIN_ID:
            memcpy(tx->chain_id + pos, src, n);
            break;
        case TX_F_NONCE:
            memcpy(tx->nonce + pos, src, n);
            break;
        case TX_F_GAS_TIP_CAP:
            memcpy(tx->gas_tip_cap + pos, src, n);
            break;
        case TX_F_GAS_FEE_CAP:
            memcpy(tx->gas_fee_cap + pos, src, n);
            break;
        case TX_F_GAS:
            memcpy(tx->gas + pos, src, n);
            break;
        case TX_F_TO:
            memcpy(tx->to + pos, src, n);
            break;
        case TX_F_VALUE:
            memcpy(tx->value + pos, src, n);
            break;
        case TX_F_DESCRIPTOR:
            memcpy(tx->descriptor + pos, src, n);
            break;
        default:
            // TX_F_DATA, TX_F_ACCESS_LIST, TX_F_EXTRA_PARAMS: hashed by the
            // caller, not retained
            break;
    }
    return true;
}

/**
 * Close the current field, run its end-of-field checks and move to the next.
 */
static bool field_end(tx_stream_t *s, zond_tx_t *tx) {
    // every retained fixed-size field is at most ADDRESS_LENGTH bytes
    uint8_t len8 = (uint8_t) s->field_len;

    switch (s->field) {
        case TX_F_LIST:
        case TX_F_TO:
        case TX_F_DATA:
        case TX_F_ACCESS_LIST:
            break;
        case TX_F_CHAIN_ID:
            tx->chain_id_len = len8;
            break;
        case TX_F_NONCE:
            tx->nonce_len = len8;
            break;
        case TX_F_GAS_TIP_CAP:
            tx->gas_tip_cap_len = len8;
            break;
        case TX_F_GAS_FEE_CAP:
            tx->gas_fee_cap_len = len8;
            break;
        case TX_F_GAS:
            tx->gas_len = len8;
            break;
        case TX_F_VALUE:
            tx->value_len = len8;
            break;
        case TX_F_DESCRIPTOR:
            // ML-DSA-87 wallet: wallet_type 0x01, metadata 0x00 0x00
            if (tx->descriptor[0] != 0x01 || tx->descriptor[1] != 0x00 ||
                tx->descriptor[2] != 0x00) {
                return false;
            }
            tx->descriptor_len = len8;
            break;
        case TX_F_EXTRA_PARAMS:
            // last field: the outer list must close exactly here
            if (s->list_remaining != 0) {
                return false;
            }
            break;
        default:
            return false;
    }

    s->field = (tx_field_e) (s->field + 1);
    s->in_payload = false;
    s->hdr_len = 0;
    s->hdr_need = 0;
    s->field_len = 0;
    s->field_pos = 0;
    return true;
}

tx_stream_status_e tx_stream_feed(tx_stream_t *s, zond_tx_t *tx, const uint8_t *chunk, size_t len) {
    size_t i = 0;

    if (s == NULL) {
        return TX_STREAM_ERROR;
    }
    if (s->failed) {
        return TX_STREAM_ERROR;
    }
    if (tx == NULL || (chunk == NULL && len > 0)) {
        return stream_fail(s);
    }
    if (len > TX_MAX_TOTAL_LEN - s->total_len) {
        return stream_fail(s);
    }
    s->total_len += (uint32_t) len;

    while (i < len) {
        if (s->field == TX_F_DONE) {
            return stream_fail(s);  // bytes after the end of the outer list
        }

        if (s->field == TX_F_TYPE) {
            if (chunk[i] != 0x02) {
                return stream_fail(s);
            }
            i++;
            s->field = TX_F_LIST;
            continue;
        }

        if (!s->in_payload) {
            bool is_list;
            bool single;
            uint32_t flen;
            uint32_t hdr_cost;

            s->hdr[s->hdr_len++] = chunk[i++];
            if (s->hdr_need == 0) {
                s->hdr_need = rlp_header_need(s->hdr[0]);
                if (s->hdr_need == 0) {
                    return stream_fail(s);
                }
            }
            if (s->hdr_len < s->hdr_need) {
                continue;  // header continues in the next chunk
            }

            if (!rlp_header_decode(s->hdr, s->hdr_len, &is_list, &single, &flen)) {
                return stream_fail(s);
            }

            if (s->field == TX_F_LIST) {
                if (!is_list || flen == 0) {
                    return stream_fail(s);
                }
                s->list_remaining = flen;
                if (!field_end(s, tx)) {
                    return stream_fail(s);
                }
                continue;
            }

            // Header and payload must both fit in what is left of the outer list.
            // A single byte item's prefix is its payload, so it costs nothing extra.
            hdr_cost = single ? 0 : s->hdr_need;
            if (hdr_cost > s->list_remaining || flen > s->list_remaining - hdr_cost) {
                return stream_fail(s);
            }
            s->list_remaining -= hdr_cost;

            if (!field_begin(s, tx, is_list, flen)) {
                return stream_fail(s);
            }

            if (single) {
                if (!field_store(s, tx, &s->hdr[0], 1)) {
                    return stream_fail(s);
                }
                s->field_pos = 1;
                s->list_remaining -= 1;
            }
            if (s->field_pos == s->field_len) {
                // empty item or single byte item: nothing more to receive
                if (!field_end(s, tx)) {
                    return stream_fail(s);
                }
            }
            continue;
        }

        // payload bytes of the current field
        {
            uint32_t want = s->field_len - s->field_pos;
            size_t avail = len - i;
            uint32_t n = (want < avail) ? want : (uint32_t) avail;

            if (!field_store(s, tx, chunk + i, n)) {
                return stream_fail(s);
            }
            s->field_pos += n;
            s->list_remaining -= n;
            i += n;

            if (s->field_pos == s->field_len) {
                if (!field_end(s, tx)) {
                    return stream_fail(s);
                }
            }
        }
    }

    return (s->field == TX_F_DONE) ? TX_STREAM_FINISHED : TX_STREAM_PROCESSING;
}
