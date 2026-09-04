#ifndef MLDSA87_H
#define MLDSA87_H

#include "constant.h"
#include <stdint.h>
#include <stdbool.h>
#include "error.h"
#include <stdlib.h>

ErrorCode new_mldsa87_from_seed(uint8_t (*seed)[SEED_BYTES]);
void extract_signature(uint8_t *signatureMessage, uint8_t *sig);

#endif
