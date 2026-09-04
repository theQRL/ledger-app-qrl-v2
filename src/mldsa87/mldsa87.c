#include "mldsa87.h"
#include "sign.h"
#include "utils.h"
#include "cx.h"
#include <string.h>
#include <stdarg.h>
#include "globals.h"
#include "os_pic.h"

ErrorCode new_mldsa87_from_seed(uint8_t (*seed)[SEED_BYTES]) {
    int err = 0;
    err = crypto_sign_keypair(seed);
    if (err != 0) {
        return err;
    }
    return ERR_NONE;
}
