# SPDX-License-Identifier: Apache-2.0
# Pinned release build environment (design §6.2). The toolchain inside is installed by the same
# build/setup-toolchain.sh a plain Linux builder uses, so both builders run identical versions.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils git gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m builder
USER builder
COPY --chown=builder setup-toolchain.sh /tmp/setup-toolchain.sh
RUN bash /tmp/setup-toolchain.sh
ENV PATH=/home/builder/.local/zig-0.13.0:/home/builder/.cargo/bin:$PATH
WORKDIR /flowmesh
