#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tx_stream.h"

/*
 * The first input byte selects the APDU chunk size (1..255); the rest of the
 * input is fed to the streaming parser in chunks of that size, so RLP headers
 * and payloads get split at arbitrary boundaries.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    tx_stream_t s;
    zond_tx_t tx;

    if (size == 0) {
        return 0;
    }
    size_t chunk = (size_t) (data[0] % 255) + 1;
    data++;
    size--;

    tx_stream_init(&s, &tx);
    while (size > 0) {
        size_t n = size < chunk ? size : chunk;
        if (tx_stream_feed(&s, &tx, data, n) == TX_STREAM_ERROR) {
            break;
        }
        data += n;
        size -= n;
    }
    return 0;
}
