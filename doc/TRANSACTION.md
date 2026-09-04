# QRL v2.0 Transaction Serialization

## Overview

The app signs QRL v2.0 dynamic-fee (EIP-1559-style, type `0x02`) transactions.
The host streams the **unsigned signing preimage** to the device; the device
hashes exactly the bytes it receives, displays the decoded fields for user
confirmation, and returns a detached ML-DSA-87 signature.

## Signing preimage

```text
preimage = 0x02 || rlp([chain_id, nonce, gas_tip_cap, gas_fee_cap, gas,
                        to, value, data, access_list, descriptor,
                        extra_params])
sighash  = Keccak-256(preimage)          // legacy Keccak, 32 bytes
```

The device signs the 32-byte `sighash` (it is not hashed again) with the
fixed 8-byte signing context `5a4f4e4401010000`
(`"ZOND" || version 0x01 || descriptor 01 00 00`). Signing is hedged.

## Fields

| # | Field | Constraint enforced by the device |
| ---: | --- | --- |
| 1 | `chain_id` | ≤ 32 bytes |
| 2 | `nonce` | ≤ 8 bytes |
| 3 | `gas_tip_cap` | ≤ 32 bytes (maxPriorityFeePerGas) |
| 4 | `gas_fee_cap` | ≤ 32 bytes (maxFeePerGas) |
| 5 | `gas` | ≤ 8 bytes |
| 6 | `to` | exactly 64 bytes, or empty (contract creation) |
| 7 | `value` | ≤ 32 bytes |
| 8 | `data` | opaque |
| 9 | `access_list` | opaque RLP item |
| 10 | `descriptor` | exactly `01 00 00` (ML-DSA-87) |
| 11 | `extra_params` | reserved; must be empty, but present in the signed list |

The list must contain exactly these 11 items; trailing or missing items fail
parsing. Maximum streamed transaction size is `MAX_TRANSACTION_LEN`
(currently 510 bytes, `src/constants.h`).

The full on-chain transaction appends `signature` (4,627 bytes) and
`public_key` (2,592 bytes) after `extra_params`; the device never receives or
parses that signed envelope; assembling it is the host's job.

## Signature

ML-DSA-87 (FIPS 204): 4,627-byte detached signature, returned to the host in
chunks (see `APP_SPECIFICATION.md`). The device verifies its own signature
before releasing it.

## See also

- `APP_SPECIFICATION.md`: APDU interface
- The QRL-Ledger-v1 wallet profile in the QRL v2.0 specifications
  repository (derivation, addresses, signing context)
