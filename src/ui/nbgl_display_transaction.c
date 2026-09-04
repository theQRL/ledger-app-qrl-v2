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
#include <string.h>   // memset

#include "os.h"
#include "glyphs.h"
#include "os_io_seproxyhal.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"
#include "tx_format.h"
#include "validate.h"
#include "menu.h"
#include "address.h"

static char g_from_address[1 + ADDRESS_SIZE * 2 + 1];
static char g_amount[TX_FORMAT_MAX_AMOUNT_LEN + 5];
static char g_to_address[1 + ADDRESS_SIZE * 2 + 1];
static char g_max_fees[TX_FORMAT_MAX_AMOUNT_LEN + 5];
static char g_chain_id[TX_FORMAT_MAX_DECIMAL_DIGITS + 1];
static char g_nonce[21];
static char g_gas_limit[21];
static char g_gas_tip_cap[TX_FORMAT_MAX_AMOUNT_LEN + 5];
static char g_tx_hash[65];

static nbgl_contentTagValue_t pairs[9];
static nbgl_contentTagValueList_t pairList;

static void bytes_to_lower_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hex[bytes[i] >> 4];
        out[2 * i + 1] = hex[bytes[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

// called when long press button on 3rd page is long-touched or when reject footer is touched
static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main.
    // The spinner belongs only on the signing path: showing "Signing" after the
    // user pressed Reject is misleading, and the frame is transient on that path
    // (rejection only sends SW_DENY), which made the screen count racy.
    if (confirm) {
        nbgl_useCaseSpinner("Signing");
        validate_transaction(confirm);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        validate_transaction(confirm);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

void print_tx_utils(zond_tx_t *tx) {
    PRINTF("======== ZOND TX ========\n");
    PRINTF("Chain ID: 0x");
    for (int i = 0; i < tx->chain_id_len; i++) PRINTF("%02x", tx->chain_id[i]);
    PRINTF("\n");

    PRINTF("Nonce: 0x");
    for (int i = 0; i < tx->nonce_len; i++) PRINTF("%02x", tx->nonce[i]);
    PRINTF("\n");

    PRINTF("Gas Tip Cap: 0x");
    for (int i = 0; i < tx->gas_tip_cap_len; i++) PRINTF("%02x", tx->gas_tip_cap[i]);
    PRINTF("\n");

    PRINTF("Gas Fee Cap: 0x");
    for (int i = 0; i < tx->gas_fee_cap_len; i++) PRINTF("%02x", tx->gas_fee_cap[i]);
    PRINTF("\n");

    PRINTF("Gas: 0x");
    for (int i = 0; i < tx->gas_len; i++) PRINTF("%02x", tx->gas[i]);
    PRINTF("\n");

    PRINTF("To: 0x");
    for (int i = 0; i < ADDRESS_LENGTH; i++) PRINTF("%02x", tx->to[i]);
    PRINTF("\n");

    PRINTF("Value: 0x");
    for (int i = 0; i < tx->value_len; i++) PRINTF("%02x", tx->value[i]);
    PRINTF("\n");
    PRINTF("================\n");
}

// Public function to start the transaction review
// - Check if the app is in the right state for transaction review
// - Format the amount and address strings in g_amount and g_address buffers
// - Display the first screen of the transaction review
// - Display a warning if the transaction is blind-signed
int ui_display_transaction_bs_choice(bool is_blind_signed, zond_tx_t *tx) {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    print_tx_utils(tx);

    PRINTF("DERIVE ADDRESS START\n");
    nbgl_useCaseSpinner("Getting address");
    cx_err_t error =
        address_from_bip32_path(G_context.bip32_path, G_context.bip32_path_len, G_context.address);
    if (error != CX_OK) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }
    PRINTF("DERIVE ADDRESS END\n");
    PRINTF("from ");
    for (int i = 0; i < ADDRESS_SIZE; i++) {
        PRINTF("%02x", G_context.address[i]);
    }
    PRINTF("\n");

    // Format from address
    memset(g_from_address, 0, sizeof(g_from_address));
    if (!format_checksummed_address(G_context.address, g_from_address, sizeof(g_from_address))) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    // Format amount
    char amount[TX_FORMAT_MAX_AMOUNT_LEN] = {0};
    if (!format_qrl_amount(tx->value, tx->value_len, amount, sizeof(amount)))
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    PRINTF("amount %s\n", amount);
    memset(g_amount, 0, sizeof(g_amount));
    snprintf(g_amount, sizeof(g_amount), "QRL %s", amount);

    // Format to address
    memset(g_to_address, 0, sizeof(g_to_address));
    if (!format_checksummed_address(tx->to, g_to_address, sizeof(g_to_address))) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }
    PRINTF("to %s\n", g_to_address);

    // Format max_fees
    uint8_t fee_product[TX_FORMAT_MAX_INTEGER_BYTES];
    size_t fee_product_len = sizeof(fee_product);
    char max_fees[TX_FORMAT_MAX_AMOUNT_LEN] = {0};
    if (!multiply_uint8_arrays(tx->gas_fee_cap,
                               tx->gas_fee_cap_len,
                               tx->gas,
                               tx->gas_len,
                               fee_product,
                               &fee_product_len) ||
        !format_qrl_amount(fee_product, fee_product_len, max_fees, sizeof(max_fees)))
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    PRINTF("max fees %s\n", max_fees);
    memset(g_max_fees, 0, sizeof(g_max_fees));
    snprintf(g_max_fees, sizeof(g_max_fees), "QRL %s", max_fees);

    // Setup data to display
    if (!uint8_array_to_decimal(tx->chain_id, tx->chain_id_len, g_chain_id, sizeof(g_chain_id)) ||
        !uint8_array_to_decimal(tx->gas, tx->gas_len, g_gas_limit, sizeof(g_gas_limit)) ||
        !format_qrl_amount(tx->gas_tip_cap, tx->gas_tip_cap_len, amount, sizeof(amount)))
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    snprintf(g_gas_tip_cap, sizeof(g_gas_tip_cap), "QRL %s", amount);

    size_t count = 0;
#define ADD_PAIR(label, text)          \
    do {                               \
        pairs[count].item = (label);   \
        pairs[count++].value = (text); \
    } while (0)
    ADD_PAIR("From", g_from_address);
    ADD_PAIR("Amount", g_amount);
    ADD_PAIR("To", g_to_address);
    ADD_PAIR("Chain ID", g_chain_id);
    ADD_PAIR("Gas limit", g_gas_limit);
    ADD_PAIR("Priority fee / gas", g_gas_tip_cap);
    ADD_PAIR("Max fees", g_max_fees);
    if (N_storage.display_nonce) {
        if (!uint8_array_to_decimal(tx->nonce, tx->nonce_len, g_nonce, sizeof(g_nonce)))
            return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
        ADD_PAIR("Nonce", g_nonce);
    }
    if (N_storage.display_tx_hash) {
        bytes_to_lower_hex(G_context.tx_info.m_hash, 32, g_tx_hash);
        ADD_PAIR("Transaction hash", g_tx_hash);
    }
#undef ADD_PAIR

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = count;
    pairList.pairs = pairs;

    if (is_blind_signed) {
        // Start blind-signing review flow
        nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                       &pairList,
                                       &ICON_APP_BOILERPLATE,
                                       "Review transaction\n",
                                       NULL,
#ifdef SCREEN_SIZE_WALLET
                                       "Sign transaction\n",
#else
                                       NULL,
#endif
                                       NULL,
                                       review_choice);
    } else {
        // Start review flow
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &pairList,
                           &ICON_APP_BOILERPLATE,
                           "Review transaction\n",
                           NULL,
#ifdef SCREEN_SIZE_WALLET
                           "Sign transaction\n",
#else
                           NULL,
#endif
                           review_choice);
    }
    return 0;
}

// Flow used to display a clear-signed transaction
int ui_display_transaction(zond_tx_t *tx) {
    return ui_display_transaction_bs_choice(false, tx);
}
