# QRL v2.0 Ledger Application

Ledger hardware wallet application for QRL v2.0, the post-quantum blockchain.
Signs QRL v2.0 dynamic-fee transactions with **ML-DSA-87** (FIPS 204) using
keys derived on-device. Supports Nano S+, Nano X, Stax, and Flex.

- **Signature scheme:** ML-DSA-87 with 2,592-byte public keys, 4,627-byte
  hedged signatures, and a descriptor-bound 8-byte signing context
- **Addresses:** 64-byte `SHAKE256(descriptor ‖ pk)` with checksummed
  `Q` + 128-hex display
- **Derivation:** BIP-32 path `m/44'/238'/account'/change/index` (see the
  QRL-Ledger-v1 wallet profile for how this differs from software wallets)

## Documentation

- [`APP_SPECIFICATION.md`](APP_SPECIFICATION.md): APDU interface
- [`doc/TRANSACTION.md`](doc/TRANSACTION.md): transaction preimage and
  signing format

## Build

Builds run in Ledger's dev-tools container:

```sh
docker run --rm -v "$PWD:/app" -w /app \
    ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
    bash -c 'BOLOS_SDK=$NANOSP_SDK make -j'
```

Substitute `$NANOX_SDK`, `$STAX_SDK`, or `$FLEX_SDK` for the other targets.

## Test

Functional tests run with [Ragger](https://github.com/LedgerHQ/ragger) on
Speculos. The dev-tools image needs the test dependencies added once:

```sh
docker run --rm -v "$PWD:/app" -w /app/tests <image-with-test-deps> \
    pytest --device nanosp
```

(Add the packages from `tests/requirements.txt` to the dev-tools image's
`/opt/venv` once with `pip install -r tests/requirements.txt`.)

Screen snapshots regenerate with `--golden_run` after intentional UI changes.

### End-to-end devnet test

[`tests/e2e/`](tests/e2e/README.md) contains a full runbook and scripts that
prove a device-signed transaction is accepted by a real QRL v2.0 node: spin up
a private Kurtosis devnet, fund the device account, sign on Speculos, verify
the signature independently with `@theqrl/wallet.js` (from npm, pinned), and
broadcast.

## Security model

Key material never leaves the device; derivation is rooted in the Ledger OS
BIP-39 seed. A wallet created by this app is recoverable only through a
Ledger device with the same recovery phrase running this app. It is
deliberately not restorable in QRL software wallets, and software backups
cannot restore it. The device verifies every signature it produces before
releasing it, and secret signing intermediates are wiped from NVM after each
operation.

## Flash wear and scratch memory

Post-quantum signing is demanding for a small device. That has one practical
consequence, described here in full.

### Why the app writes to storage

Your Ledger has 28–40 KB of working memory, shared with the screen and the
operating system. One ML-DSA-87 signature needs about 63 KB of scratch space.
It does not fit. So the app borrows a corner of the device's storage (flash)
while it does the maths.

Flash behaves like a whiteboard. You can rewrite it, but not forever. This
hardware does not spread wear across the chip, so repeated signing rewrites the
same patch.

### What ends up in that scratch space

That memory survives a power-off, so it matters what is written there.

- Your recovery phrase and private key never do. They stay in the secure chip's
  protected storage and in short-lived working memory.
- What gets written are intermediate results, derived from your key. They are
  not the key. On their own they cannot rebuild it or forge a signature.
- The app erases them when signing finishes, before handing the signature back
  to your computer.
- Lose power mid-signature and some can survive until the next one. The app
  clears them at startup.

Reading any of it means physically attacking the secure chip, which is the
attack a hardware wallet exists to resist.

### Mitigations

The first working version of this app focused on getting the mathematics right
on tight hardware. We then optimised it to write less.

- Scratch data that never needed to be in storage now stays in working memory.
- Writes are aligned to the chip's page size, so one write no longer wears two
  pages.
- Settings moved to their own page. Changing a setting no longer wears the area
  signing uses.
- The retry loop is capped, so an unlucky run cannot spin and write
  indefinitely.
- Leftover scratch is cleared at startup, after an interrupted signature.

Each signature now causes about 30 rewrites of the busiest area, down from
about 439. Roughly a 93% cut.

### Context

Signing is not the only thing writing to this memory. Installing and removing
apps, firmware updates, settings changes, and data stored by other apps all
draw on the same budget, on any hardware wallet. After the optimisation work,
our signing is a modest contributor rather than the dominant one.

We are not quoting a "you get N signatures" number. That depends on how many
rewrites the secure chip is rated for, which is Ledger's figure to publish.

If this memory did wear out, the app stops signing. It does not sign something
wrong: the device checks every signature before releasing it. Your recovery
phrase still restores your funds on another device.

### What may improve

Ledger's SDK keeps developing and now ships its own post-quantum signing that
runs entirely in working memory. As it matures, and as we keep optimising, the
scratch writing should keep falling. Moving to an all-in-memory implementation
would remove this trade-off rather than shrink it. We are tracking Ledger's SDK
development and will upgrade this app as we are able.  Likewise, as we stress-test
the app, we may find further optimisations that reduce writes or be better placed
to estimate a "you get N signatures" number.
