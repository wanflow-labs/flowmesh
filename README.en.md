# FlowMesh

**Connect your Linux servers and OpenWrt routers to a private Wanflow network.** An open-source Rust client with a small resource footprint.

[**Create a free mesh →**](https://console.wanflow.com/order/mesh/configure?tier=free&utm_source=github&utm_medium=readme&utm_campaign=flowmesh&utm_content=en) · [Wanflow console](https://console.wanflow.com/) · [Apps for other platforms](https://www.wanflow.com/downloads) · [中文](README.md)

Bring your home NAS, office servers, cloud instances, laptops and phones onto one encrypted private network with Wanflow FlowMesh. Devices connect directly where possible and automatically use Wanflow relays otherwise. No inbound ports to open and no VPN gateway to host yourself.

Create your mesh, add devices and manage access in the Wanflow console. FlowMesh connects your Linux and OpenWrt devices, while Wanflow hosts the control service and relays.

## What can you do with it?

| Your use case | How it works |
|---|---|
| **Reach your home NAS or services while away** | Install FlowMesh on a home Linux device or OpenWrt router, then connect your laptop or phone with a Wanflow app; configure subnet routing to reach the rest of your home network |
| **Connect office and cloud servers** | Join Linux servers to the same mesh, reach services over mesh IPs, and manage access in the console |
| **Connect an OpenWrt router** | Join Wanflow through the LuCI interface, with optional subnet sharing or exit-node routing; see the [OpenWrt installation guide](docs/install.md#openwrt-routers) |

## Get started

### 1. Create a free mesh in Wanflow

Open [**Create a free mesh**](https://console.wanflow.com/order/mesh/configure?tier=free&utm_source=github&utm_medium=readme&utm_campaign=flowmesh&utm_content=en), sign up or log in, and complete setup. The free plan has no expiry; check the creation page for current allowances and features. See [plans](https://www.wanflow.com/pricing) for other options.

### 2. Connect your first device

- **Linux server:** In your mesh console, choose "Add device → Linux server" and run the generated installation command on your server. It includes your mesh address and auth key; do not share it publicly.
- **OpenWrt router:** Follow the [installation guide](docs/install.md#openwrt-routers) to install FlowMesh and its LuCI interface. Open "Services → FlowMesh", paste the command from the console, and join.

For manual installation, upgrades or removal, see the [Linux and OpenWrt installation guide](docs/install.md).

### 3. Add a second device and check the connection

Connect another Linux or OpenWrt device, or install the Wanflow app for [macOS, Windows, iOS or Android](https://www.wanflow.com/downloads) and join the same mesh. Once both devices appear online in the console, run this on your Linux device:

```bash
flowmesh status
flowmesh ping 'OTHER_DEVICE_MESH_IP'
```

Replace the placeholder with the actual mesh IP shown in the console. You can then use that IP to reach SSH, web apps or other services on the peer. The service must be listening, and both the mesh access policy and the device firewall must allow the connection. To reach a NAS or other device behind a router, also configure and approve subnet routes; see [joining a network](docs/install.md#3-joining-a-mesh).

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

## What it does

- **Direct, encrypted tunnels** (WireGuard) between devices, through NAT where possible; otherwise over Wanflow's relays, including the high-performance peer relays
- **Relay modes** set from the Wanflow console: direct when possible, prefer relays, or relay only
- **Access control** from the console (ACLs and tags), **subnet routers** to reach a whole office network, **exit nodes** to send internet traffic through a chosen site
- **Names instead of addresses** (MagicDNS), with a built-in resolver
- **SSH by mesh identity** (`--ssh`): log in as the users your policy allows, no keys or passwords to hand out
- **Share a local service** with the mesh (`flowmesh serve`): a web app, files, or a TCP port
- **Operations built in**: `status`, `ping`, `whois`, `netcheck`, `metrics` (Prometheus), `bugreport`
- **Packages** for Debian/Ubuntu (deb) and RHEL/Rocky/Alma (rpm), static binaries for x86_64 and aarch64, a hardened systemd unit
- **OpenWrt routers** (21.02 to 25.12): a signed package feed added with one command, with a LuCI page ([install](docs/install.md#openwrt-routers))

## Trust, by design

- **Open source**, Apache-2.0. Read every line that runs on your machine.
- **No telemetry.** `flowmeshd` connects only to your mesh's control server, the relays it names, your peers and your DNS servers. No default server, no auto-update, nothing phoning home.
- **Reproducible builds.** Released binaries can be rebuilt from this source byte for byte ([how](docs/reproducible-builds.md)).
- **Memory safe.** Rust with `unsafe` forbidden in every crate.

## Protocol and compatibility

FlowMesh independently implements the Tailscale coordination protocol and interoperates with official Tailscale clients in the same mesh. See the [CLI documentation](docs/protocol/cli.md) for command-line compatibility and [deviations.md](docs/deviations.md) for known differences and feature limitations.

## About Wanflow

Wanflow (万联云网关) provides managed mesh networking, with a central console for devices, access policies and relays. This repository contains the open-source Linux / OpenWrt client under Apache-2.0; hosted service allowances and features depend on your plan.

[**Create a free mesh**](https://console.wanflow.com/order/mesh/configure?tier=free&utm_source=github&utm_medium=readme&utm_campaign=flowmesh&utm_content=en) · [About Wanflow](https://www.wanflow.com) · [View plans](https://www.wanflow.com/pricing)

## Development

    make check      # fmt + clippy + test + deny + similarity scan
    make lab-up     # local interop lab in Docker (see lab/README.md)
    make release    # reproducible release build in a pinned container

Protocol behavior is learned by observing real clients in the lab, never by copying code; the observations are in [docs/protocol](docs/protocol). Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

"Tailscale" is a trademark of Tailscale Inc. and "WireGuard" a registered trademark of Jason A. Donenfeld; neither is affiliated with or endorses this project.
