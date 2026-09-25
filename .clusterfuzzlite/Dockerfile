FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:687f4071ca076c92afcbb9f9540c4b21ddfc0580a3fe71d6cc1b27edab8905fd AS LITE_BUILDER

# Base image with clang toolchain
FROM gcr.io/oss-fuzz-base/base-builder@sha256:b1f0fce811b848e117a4809f8ccf1bdf94d1b5d5406d19e8512ac3f0ce958b3c

# Copy the project's source code.
COPY . $SRC/app-boilerplate
COPY --from=LITE_BUILDER /opt/ledger-secure-sdk $SRC/app-boilerplate/BOLOS_SDK

# Working directory for build.sh
WORKDIR $SRC/app-boilerplate

# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
