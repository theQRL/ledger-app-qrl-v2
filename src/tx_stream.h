#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "tx_types.h"

/**
 * Reset the parser state and the output structure before the first chunk.
 *
 * @param[out] s   parser state
 * @param[out] tx  decoded transaction fields
 */
void tx_stream_init(tx_stream_t *s, zond_tx_t *tx);

/**
 * Feed the next chunk of the serialized transaction (0x02 || rlp([...])).
 *
 * The parser never looks ahead: every byte is consumed exactly once and the
 * position is kept in `s` between calls, so chunk boundaries may fall anywhere,
 * including inside an RLP header. Hashing of the raw bytes is the caller's job;
 * this module does not depend on the SDK.
 *
 * Validation rules: canonical RLP only (no leading zero in
 * a length, long form only for 56+ bytes, a lone byte below 0x80 encoded as
 * itself), no leading zero in integer fields, `data` must be a string and
 * `access_list` a list.
 *
 * @return TX_STREAM_PROCESSING while more bytes are expected,
 *         TX_STREAM_FINISHED once the outer list is complete and valid,
 *         TX_STREAM_ERROR on malformed input (sticky until tx_stream_init).
 */
tx_stream_status_e tx_stream_feed(tx_stream_t *s, zond_tx_t *tx, const uint8_t *chunk, size_t len);
