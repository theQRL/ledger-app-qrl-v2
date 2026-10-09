FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:687f4071ca076c92afcbb9f9540c4b21ddfc0580a3fe71d6cc1b27edab8905fd AS LITE_BUILDER

# Base image with clang toolchain
FROM gcr.io/oss-fuzz-base/base-builder@sha256:3cf598908df31d5bcc8013f9040e7689daef8cbeedd0401789158fb1abd42cf4

# Copy the project's source code.
COPY . $SRC/app-boilerplate
COPY --from=LITE_BUILDER /opt/ledger-secure-sdk $SRC/app-boilerplate/BOLOS_SDK

# Working directory for build.sh
WORKDIR $SRC/app-boilerplate

# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
