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

#include <stdbool.h>  // bool

#include "crypto_helpers.h"

#include "validate.h"
#include "menu.h"
#include "sw.h"
#include "globals.h"
#include "send_response.h"
#include "sign.h"
#include "keccak256.h"

void validate_pubkey(bool choice) {
    if (choice) {
        helper_send_response_address();
    } else {
        io_send_sw(SW_DENY);
    }
}

static int crypto_sign_message(void) {
    cx_err_t error = 0;

    PRINTF("bip32_path_len %d\n", G_context.bip32_path_len);
    PRINTF("SIGNING START\n");
    error = crypto_sign_optimized(G_context.bip32_path,
                                  G_context.bip32_path_len,
                                  G_context.tx_info.m_hash,
                                  32);
    PRINTF("SIGNING END\n");
    if (error != CX_OK) {
        wipe_nvm_secrets();
        return -1;
    }
    PRINTF("bip32_path_len %d\n", G_context.bip32_path_len);
    PRINTF("VERIFY START\n");
    bool is_verified = false;
    error = crypto_verify_optimized(G_context.bip32_path,
                                    G_context.bip32_path_len,
                                    (uint8_t *) N_storage.sig,
                                    CRYPTO_BYTES,
                                    G_context.tx_info.m_hash,
                                    32,
                                    &is_verified);
    PRINTF("VERIFY END\n");
    wipe_nvm_secrets();
    if (is_verified) {
        PRINTF("SIGNATURE CORRECT\n");
    } else {
        PRINTF("SIGNATURE WRONG\n");
    }
    // for(int i = 0; i < CRYPTO_BYTES; i++) {
    //     PRINTF("%02x", N_storage.sig[i]);
    // }
    // PRINTF("\n");

    if (error != CX_OK || !is_verified) {
        return -1;
    }

    return 0;
}

void validate_transaction(bool choice) {
    if (choice) {
        G_context.state = STATE_APPROVED;

        if (crypto_sign_message() != 0) {
            G_context.state = STATE_NONE;
            io_send_sw(SW_SIGNATURE_FAIL);
        } else {
            helper_send_response_sig(0);
        }
    } else {
        G_context.state = STATE_NONE;
        io_send_sw(SW_DENY);
    }
}
