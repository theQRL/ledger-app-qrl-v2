FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:59818aebd5ec41635c8c33533a29aec39e7936e3a5b3ed89bdbf5ba316b188c9 AS LITE_BUILDER

# Base image with clang toolchain
FROM gcr.io/oss-fuzz-base/base-builder@sha256:8954f7ece3f9e0731a748ffd91ee966bc032b3340725e773aef3d7e82eb5d8b6

# Copy the project's source code.
COPY . $SRC/app-boilerplate
COPY --from=LITE_BUILDER /opt/ledger-secure-sdk $SRC/app-boilerplate/BOLOS_SDK

# Working directory for build.sh
WORKDIR $SRC/app-boilerplate

# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
