#pragma once

#include <stdint.h>

/**
 * Keccak-f[1600] permutation, 24 rounds.
 *
 * Shared by the SHAKE-128, SHAKE-256 and Keccak-256 sponges in this directory.
 * Previously each sponge carried its own byte-identical copy.
 */
void keccakf(uint64_t s[25]);
