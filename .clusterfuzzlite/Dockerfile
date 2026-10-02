FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:687f4071ca076c92afcbb9f9540c4b21ddfc0580a3fe71d6cc1b27edab8905fd AS LITE_BUILDER

# Base image with clang toolchain
FROM gcr.io/oss-fuzz-base/base-builder@sha256:0b571c53b7180e7266de67665bc3ccef35618593af5714fee0750d611dc8b1f6

# Copy the project's source code.
COPY . $SRC/app-boilerplate
COPY --from=LITE_BUILDER /opt/ledger-secure-sdk $SRC/app-boilerplate/BOLOS_SDK

# Working directory for build.sh
WORKDIR $SRC/app-boilerplate

# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
