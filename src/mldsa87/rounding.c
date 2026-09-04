#include "rounding.h"
#include "constant.h"

int32_t power2_round(int32_t *a0, int32_t a) {
    int32_t a1 = 0;

    a1 = (a + (1 << (D - 1)) - 1) >> D;
    *a0 = a - (a1 << D);
    return a1;
}

int32_t decompose(int32_t *a0, int32_t a) {
    int32_t a1 = (a + 127) >> 7;
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;

    *a0 = a - a1 * 2 * GAMMA2;
    *a0 -= (((Q_CONST - 1) / 2 - *a0) >> 31) & Q_CONST;

    return a1;
}

uint32_t make_hint(int32_t a0, int32_t a1) {
    uint32_t gt = (uint32_t) (GAMMA2 - a0) >> 31;
    uint32_t lt = (uint32_t) (a0 + GAMMA2) >> 31;
    int32_t diff = a0 + GAMMA2;
    uint32_t eq = 1U - ((uint32_t) (diff | -diff) >> 31);
    uint32_t nz = (uint32_t) (a1 | -a1) >> 31;
    return (gt | lt | (eq & nz)) & 1U;
}

int32_t use_hint(int32_t a, int32_t hint) {
    int32_t a0 = 0, a1 = 0;

    a1 = decompose(&a0, a);
    int32_t hint_zero = 1 - (int32_t) ((uint32_t) (hint | -hint) >> 31);
    int32_t positive = (int32_t) ((uint32_t) -a0 >> 31);
    int32_t mask_zero = -hint_zero;
    int32_t mask_nz = -(1 - hint_zero);
    int32_t mask_pos = -positive;
    return (a1 & mask_zero) | (((a1 + 1) & 15) & mask_nz & mask_pos) |
           (((a1 - 1) & 15) & mask_nz & ~mask_pos);
}
