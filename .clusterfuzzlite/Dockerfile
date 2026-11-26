FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:42c9acbd60ff7649ae64b4c62d74ff088c8f857415813b4559d610757e0b4178 AS LITE_BUILDER

# Base image with clang toolchain
FROM gcr.io/oss-fuzz-base/base-builder@sha256:1f9cf74bc3d7029b528494542f9d9851b256dceed38d3f420989434dc5ae0760

# Copy the project's source code.
COPY . $SRC/app-boilerplate
COPY --from=LITE_BUILDER /opt/ledger-secure-sdk $SRC/app-boilerplate/BOLOS_SDK

# Working directory for build.sh
WORKDIR $SRC/app-boilerplate

# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
