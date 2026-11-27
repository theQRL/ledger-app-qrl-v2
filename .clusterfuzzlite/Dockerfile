FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:45ec491f28489aa0337eea8d50e9962a700ed41054081ee1b639bc1b128e6a32 AS LITE_BUILDER

# Base image with clang toolchain
FROM gcr.io/oss-fuzz-base/base-builder@sha256:8954f7ece3f9e0731a748ffd91ee966bc032b3340725e773aef3d7e82eb5d8b6

# Copy the project's source code.
COPY . $SRC/app-boilerplate
COPY --from=LITE_BUILDER /opt/ledger-secure-sdk $SRC/app-boilerplate/BOLOS_SDK

# Working directory for build.sh
WORKDIR $SRC/app-boilerplate

# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
