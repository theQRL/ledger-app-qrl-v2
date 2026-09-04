#pragma once

#include <stdbool.h>  // bool
#include "rlp_decode.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define ICON_APP_BOILERPLATE C_app_qrl_14px
#define ICON_APP_HOME        C_home_qrl_14px
#define ICON_APP_WARNING     C_icon_warning
#elif defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_APP_BOILERPLATE C_app_qrl_64px
#define ICON_APP_HOME        ICON_APP_BOILERPLATE
#define ICON_APP_WARNING     C_Warning_64px
#endif

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(bool);

/**
 * Display address on the device and ask confirmation to export.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_address(void);

/**
 * Display transaction information on the device and ask confirmation to sign.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_transaction(zond_tx_t *);

int ui_display_transaction_bs_choice(bool is_blind_signed, zond_tx_t *tx);

/**
 * Display blind-sign transaction information on the device and ask confirmation to sign.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
