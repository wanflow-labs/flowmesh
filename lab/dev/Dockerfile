# SPDX-License-Identifier: Apache-2.0
# flowmesh lab dev container: Rust toolchain + network debugging tools. Builds and runs flowmesh inside the lab network.
FROM rust:1.88-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iputils-ping tcpdump netcat-openbsd procps python3-scapy \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
CMD ["sleep", "infinity"]
