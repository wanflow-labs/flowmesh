# SPDX-License-Identifier: Apache-2.0
# Lab subnet router: the dev image plus iptables (Debian's default, nf_tables backend) and nftables,
# so flowmeshd's forwarding rules can be exercised with either tool (lab/scripts/subnet_router_check.sh).
FROM flowmesh-lab/dev:local
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends iptables nftables && rm -rf /var/lib/apt/lists/*
