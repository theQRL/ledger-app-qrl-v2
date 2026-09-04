/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove

#include "os.h"
#include "cx.h"
#include "crypto_helpers.h"
#include "ledger_assert.h"
#include "nbgl_use_case.h"

#include "address.h"
#include "address_format.h"

#include "constant.h"
#include "mldsa87.h"
#include "shake256.h"
#include "globals.h"

cx_err_t address_from_bip32_path(const uint32_t bip32_path[],
                                 size_t bip32_path_len,
                                 uint8_t address[ADDRESS_SIZE]) {
    uint8_t raw_seed[64] = {0};
    cx_err_t err =
        os_derive_bip32_no_throw(CX_CURVE_SECP256K1, bip32_path, bip32_path_len, raw_seed, NULL);
    if (err != CX_OK) {
        return err;
    }
    uint8_t mldsa87_seed[32] = {0};
    for (int i = 0; i < 32; i++) {
        mldsa87_seed[i] = raw_seed[i];
    }
    explicit_bzero(raw_seed, sizeof(raw_seed));
    nbgl_useCaseSpinner("Getting address");
    ErrorCode mldsa_err = new_mldsa87_from_seed(&mldsa87_seed);
    if (mldsa_err != ERR_NONE) {
        return CX_INTERNAL_ERROR;
    }

    uint8_t desc[DESCRIPTOR_BYTES] = {1, 0, 0};  // ML-DSA-87 descriptor

    // address = SHAKE256_XOF(descriptor || pk, 64)
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, desc, DESCRIPTOR_BYTES);
    shake256_absorb(&ctx, (const uint8_t *) N_storage.pk, CRYPTO_PUBLIC_KEY_BYTES);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, address, ADDRESS_SIZE);
    shake256_clear(&ctx);
    return 0;
}
