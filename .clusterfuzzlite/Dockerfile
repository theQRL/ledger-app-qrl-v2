FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:70522508d5ced07524872732b1fa5f5eeca54ec9509addb3be2a30ffb3dc228a AS LITE_BUILDER

# Base image with clang toolchain
FROM gcr.io/oss-fuzz-base/base-builder@sha256:8b4a73d83374b298a0a771eeec9a1d44ceff3416a678b7d7946303389d022aca

# Copy the project's source code.
COPY . $SRC/app-boilerplate
COPY --from=LITE_BUILDER /opt/ledger-secure-sdk $SRC/app-boilerplate/BOLOS_SDK

# Working directory for build.sh
WORKDIR $SRC/app-boilerplate

# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
