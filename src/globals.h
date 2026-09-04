#pragma once

#include <stddef.h>
#include <stdint.h>

#include "ux.h"

#include "io.h"
#include "types.h"
#include "constants.h"
#include "polyvec.h"
#include "poly.h"

/**
 * Global context for user requests.
 */
extern global_ctx_t G_context;

/**
 * Global structure for NVM data storage.
 */
typedef struct internal_storage_t {
    PolyVecK t1;
    PolyVecK w1;
    PolyVecK w0;
    PolyVecK h;
    PolyVecL y;
    PolyVecL z;
    Poly cp;
    union {
        PolyVecK t0;
        uint8_t buf_verify[K * POLY_W1_PACKED_BYTES];
    } pack1;

    uint8_t sig[CRYPTO_BYTES] __attribute__((aligned(64)));
    uint8_t pk[CRYPTO_PUBLIC_KEY_BYTES] __attribute__((aligned(64)));
    uint8_t enable_blind_signing __attribute__((aligned(64)));
    uint8_t display_nonce;
    uint8_t display_tx_hash;
    uint8_t initialized;
    uint8_t is_sending_signature;
} internal_storage_t __attribute__((aligned(64)));

_Static_assert(offsetof(internal_storage_t, sig) % 64 == 0, "sig must be page aligned");
_Static_assert(offsetof(internal_storage_t, pk) % 64 == 0, "pk must be page aligned");
_Static_assert(offsetof(internal_storage_t, enable_blind_signing) % 64 == 0,
               "settings must be page aligned");

extern const internal_storage_t N_storage_real;
#define N_storage (*(volatile internal_storage_t *) PIC(&N_storage_real))
