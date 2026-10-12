# FlowMesh

**The fast, lightweight Linux client for Wanflow FlowMesh.** Open source, written in Rust.

[中文](README.md) · [Website](https://www.wanflow.com) · [Download Wanflow apps](https://www.wanflow.com/downloads) · [Install FlowMesh](docs/install.md)

FlowMesh puts your Linux servers, gateways and routers on Wanflow FlowMesh: one private, encrypted network with your offices, cloud servers, laptops and phones, wherever they are. Devices connect directly to each other whenever the network allows it and fall back to Wanflow's relays when it does not. There are no ports to open and no VPN concentrator to run.

## Why FlowMesh

Measured side by side against Tailscale 1.94.2 in the same mesh:

| | FlowMesh | Tailscale |
|---|---|---|
| TCP throughput, sending | **2.88 Gbit/s** | 2.39 Gbit/s |
| TCP throughput, receiving | 2.52 Gbit/s | 2.70 Gbit/s |
| CPU per Gbit/s (sending / receiving) | **0.29 / 0.42 core** | 0.79 / 0.81 core |
| Latency through the tunnel | **1.0 ms** | 1.6 ms |
| Daemon memory, idle, 100 peers | **10 MB** | 48 MB |
| Daemon threads | **9** | 14 |
| Binaries, daemon + command line (arm64) | **9.8 MB** | 64.8 MB |

The same throughput class at **a third to a half of the CPU** and **a fifth of the memory** — which matters most where resources are tight: a router, a small cloud instance, an edge box, or a server whose CPU should go to its real work. Leave out the SSH server at build time and the daemon shrinks by another 2 MB.

<sub>Lab measurements on one busy host (Docker on an 8-core Apple Silicon Mac, load average about 8): `iperf3` for 10 s each way between two nodes of each client on a direct path, median of 4 runs (single runs vary by up to ±20%; an earlier, quieter run gave 4.44 / 4.21 Gbit/s against 3.71 / 3.35). FlowMesh's packet path uses one core while Tailscale spreads over several, so on idle many-core machines Tailscale can gain more from the extra cores. Memory and threads were sampled while idle after both joined the same 100-node mesh. The Tailscale side is Wanflow's build of Tailscale 1.94.2, whose data path is unmodified upstream code. Compare the columns with each other, not with your hardware.</sub>

## Get started

1. **Create a mesh.** Wanflow FlowMesh has a free plan that stays free. Sign up at [wanflow.com](https://www.wanflow.com); the console gives you your mesh's address and an auth key.
2. **Install and join** on each Linux machine: the console's "Add device → Linux server" generates one command to run there. By hand it is one line too ([other ways](docs/install.md)):

   ```bash
   curl -fsSL https://github.com/wanflow-labs/flowmesh/releases/latest/download/install.sh | sh -s -- --login-server=<your mesh address> --auth-key=<key>
   ```

3. **Add your other devices** with the Wanflow app for [macOS, Windows, iOS and Android](https://www.wanflow.com/downloads). Every device in the mesh can now reach every other one by name.

## What it does

- **Direct, encrypted tunnels** (WireGuard) between devices, through NAT where possible; otherwise over Wanflow's relays, including the high-performance peer relays
- **Relay modes** set from the Wanflow console: direct when possible, prefer relays, or relay only
- **Access control** from the console (ACLs and tags), **subnet routers** to reach a whole office network, **exit nodes** to send internet traffic through a chosen site
- **Names instead of addresses** (MagicDNS), with a built-in resolver
- **SSH by mesh identity** (`--ssh`): log in as the users your policy allows, no keys or passwords to hand out
- **Share a local service** with the mesh (`flowmesh serve`): a web app, files, or a TCP port
- **Operations built in**: `status`, `ping`, `whois`, `netcheck`, `metrics` (Prometheus), `bugreport`
- **Packages** for Debian/Ubuntu (deb) and RHEL/Rocky/Alma (rpm), static binaries for x86_64 and aarch64, a hardened systemd unit

## Trust, by design

- **Open source**, Apache-2.0. Read every line that runs on your machine.
- **No telemetry.** `flowmeshd` connects only to your mesh's control server, the relays it names, your peers and your DNS servers. No default server, no auto-update, nothing phoning home.
- **Reproducible builds.** Released binaries can be rebuilt from this source byte for byte ([how](docs/reproducible-builds.md)).
- **Memory safe.** Rust with `unsafe` forbidden in every crate.

## Also speaks Tailscale

FlowMesh implements the Tailscale coordination protocol, so it also joins networks run by [headscale](https://github.com/juanfont/headscale) and works side by side with official Tailscale clients; command-line flags and output follow the official client's ([details](docs/protocol/cli.md)). It is an independent implementation with no code from Tailscale or headscale. Intended differences are listed in [deviations.md](docs/deviations.md).

## About Wanflow

Wanflow (万联云网关) offers a new site-to-site mesh networking service. Learn more at [wanflow.com](https://www.wanflow.com).

## Development

    make check      # fmt + clippy + test + deny + similarity scan
    make lab-up     # local interop lab in Docker (see lab/README.md)
    make release    # reproducible release build in a pinned container

Protocol behavior is learned by observing real clients in the lab, never by copying code; the observations are in [docs/protocol](docs/protocol). Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

"Tailscale" is a trademark of Tailscale Inc. and "WireGuard" a registered trademark of Jason A. Donenfeld; neither is affiliated with or endorses this project.
