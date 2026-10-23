# Installing and running FlowMesh (Linux + systemd)

[中文](install.zh-CN.md)

## 1. Build

```bash
cargo build --release -p flowmesh-daemon -p flowmesh-cli
```

This produces `target/release/flowmeshd` (the daemon) and `target/release/flowmesh` (the command line).

On devices with little storage (routers, for example) the SSH server can be left out, which makes `flowmeshd` about 2 MB smaller:

```bash
cargo build --release -p flowmesh-daemon -p flowmesh-cli --no-default-features
```

Such a `flowmeshd` refuses `--ssh` (`this flowmeshd was built without SSH support`); everything else is the same. The client commands `flowmesh ssh` / `flowmesh nc` use the system's own `ssh` and exist in both builds.

## 2. Install

### One command (recommended)

```bash
curl -fsSL https://github.com/wanflow-labs/flowmesh/releases/latest/download/install.sh | sh
```

The script picks the deb or rpm package or the static binaries for your system (x86_64 or aarch64; Debian/Ubuntu, RHEL/Rocky/Alma/Oracle/Fedora, openSUSE, Alpine, Arch and others), checks the download against the release's `SHA256SUMS`, installs iproute2 if it is missing and starts the service (systemd or OpenRC). Run it again to upgrade. Options join the mesh at the same time:

```bash
curl -fsSL https://github.com/wanflow-labs/flowmesh/releases/latest/download/install.sh | \
  sh -s -- --login-server=<your mesh address> --auth-key=<key> [--hostname=NAME] [--advertise-exit-node] [--ssh]
```

`--version=X.Y.Z` pins a version, `--mirror=URL` downloads from a mirror (`URL/latest/…`, `URL/vX.Y.Z/…`), `--uninstall` removes FlowMesh. The Wanflow console generates this command for each mesh.

### OpenWrt routers

OpenWrt 21.02 to 25.12 on x86_64, aarch64 and armv7 with VFP (no MIPS yet). First add the FlowMesh package feed on the router:

```sh
wget -qO- https://dl.wanflow.com/flowmesh/openwrt/add-feed.sh | sh
```

The script detects the router's architecture and package manager, imports the feed's signing key and writes the feed entry (opkg: `/etc/opkg/customfeeds.conf`; apk: `/etc/apk/repositories.d/flowmesh.list`). Running it again does not add a second entry; on an unsupported architecture it stops with an error. The feed's index is signed (usign for opkg, an apk signature for apk): an index with a wrong signature, or a package that does not match the index, is refused, and no `--force-*` or `--allow-untrusted` is needed. The feed carries the latest version only.

Then install the LuCI page (it pulls in `flowmesh`):

```sh
opkg update && opkg install luci-app-flowmesh    # OpenWrt 21.02 to 24.10
apk update && apk add luci-app-flowmesh          # OpenWrt 25.12 and later
```

For the command line only, install just `flowmesh` (`opkg install flowmesh` / `apk add flowmesh`). Do not run the Linux install command (`install.sh`) on a router: it refuses on OpenWrt, since it would replace the package's files and start a second daemon next to the service.

To join a mesh, open "Services → FlowMesh" in LuCI. In the Wanflow console, add a device to your mesh and paste the Linux install command it shows, or enter the mesh address and join key by hand; give the router a name and press "Join". The same page switches "Share local LAN", "Act as exit node" and the other settings. Settings live in `/etc/config/flowmesh` (each option is described there) and the node identity in `/etc/flowmesh/`. Installing adds a firewall zone `flowmesh` (device `flowmesh0`, forwarding to and from `lan`); removing the package deletes it.

Without LuCI, join from the command line. The service applies the settings in `/etc/config/flowmesh`, so put the name there first; `up --reset` then joins with default settings (`--accept-dns=false` leaves the router's DNS to dnsmasq) and the reload applies the rest:

```sh
uci set flowmesh.main.hostname=office-gw && uci commit flowmesh
flowmesh up --reset --accept-dns=false --hostname=office-gw \
  --login-server=https://<mesh address> --auth-key=<key>
/etc/init.d/flowmesh reload
```

With `luci-app-flowmesh` installed, `/usr/libexec/flowmesh-luci up https://<mesh address> <key> office-gw` does all three in one step (it is what the LuCI page runs, and prints `{ "ok": true }` once joined). Later changes: `uci set flowmesh.main.<option>=<value>`, `uci commit flowmesh`, `/etc/init.d/flowmesh reload`.

Upgrade: `opkg update && opkg upgrade flowmesh luci-app-flowmesh` (apk: `apk update && apk upgrade flowmesh luci-app-flowmesh`). Settings, identity and the firewall zone are kept and the router stays connected; a service you disabled (`/etc/init.d/flowmesh disable`) stays disabled. Remove: `opkg remove luci-app-flowmesh flowmesh` (apk: `apk del luci-app-flowmesh flowmesh`); the node identity in `/etc/flowmesh/` is kept, delete it by hand to remove everything.

Firmware upgrade (sysupgrade): `/etc/config/flowmesh` and `/etc/flowmesh/` are kept, but the packages are not, like every package installed after the firmware. Afterwards run the `add-feed.sh` command again and reinstall `luci-app-flowmesh` (or `flowmesh`); the router then reconnects with its kept identity and settings, without a new key.

### From a package

Debian / Ubuntu:

```bash
sudo dpkg -i flowmesh_<version>_amd64.deb      # arm64 on ARM machines
sudo systemctl enable --now flowmeshd
```

RHEL / Rocky / Alma:

```bash
sudo rpm -i flowmesh-<version>-1.x86_64.rpm    # aarch64 on ARM machines
sudo systemctl enable --now flowmeshd
```

The packages only install files; they do not enable the service. Removing the package (`dpkg -r flowmesh` / `rpm -e flowmesh`) stops the service but keeps the node identity in `/var/lib/flowmesh`; delete that directory to remove it too. The binaries are statically linked; the only other thing they need is iproute2 (the `ip` command), which the packages depend on. Every release comes with `SHA256SUMS`, and the binaries can be rebuilt from source and compared, see [reproducible builds](reproducible-builds.md).

### From source

```bash
sudo install -m 0755 target/release/flowmeshd /usr/sbin/flowmeshd
sudo install -m 0755 target/release/flowmesh /usr/bin/flowmesh
sudo install -m 0644 packaging/systemd/flowmeshd.service /etc/systemd/system/flowmeshd.service
sudo systemctl daemon-reload
sudo systemctl enable --now flowmeshd
```

## 3. Joining a mesh

FlowMesh has **no default control server**: the first `up` must name one with `--login-server`:

```bash
sudo flowmesh up --login-server=http://<control server>:<port> --auth-key=file:/root/flowmesh.key
```

- The control URL can be `http://` (plain HTTP on whatever port is given, never moved to 443; the control connection itself is encrypted by the Noise protocol) or `https://` (port 443 by default; TLS first, with the server certificate checked against the system's root certificates; for a private CA set `SSL_CERT_FILE=<CA file>`).
- `--auth-key` takes the key itself or `file:<path>` to read it from a file (so it stays out of shell history and the process list). The key is used for registration only and never written to disk.
- `up` waits until the node is Running (exit code 0). When the control server refuses, it exits 1 and prints the login URL if the server gave one. `--timeout=30s` limits the wait.
- Other common flags: `--hostname=<name>`, `--accept-dns=false` (leave the system DNS alone), `--accept-routes` (use subnet routes other nodes advertise).
- Subnet router: `--advertise-routes=192.168.1.0/24` (comma-separated for several). Once the control server approves the route, nodes with `--accept-routes` reach that network. The kernel must forward (`sysctl -w net.ipv4.ip_forward=1`, and `net.ipv6.conf.all.forwarding=1` for IPv6); FlowMesh does not change this for you and `up` warns when it is off. Traffic into the network is masqueraded (SNAT) by default, so hosts there see the router as the source; `--snat-subnet-routes=false` turns that off, and those hosts then need a route back to `100.64.0.0/10`. The forwarding rules go into the system's `iptables` (`nft` when there is none) and are removed on `down` or exit.
- Exit node: `--advertise-exit-node` (forwarding must be on as well, and the control server must approve `0.0.0.0/0,::/0`). An exit node forwards to the internet only; its own LAN and private addresses are not opened through it (advertise them as subnet routes if needed). `--stateful-filtering` blocks new connections from outside into the mesh.
- Using an exit node: `--exit-node=<IP or node name>`. From then on all internet traffic, DNS included, goes through the exit node; while it is offline that traffic is dropped rather than sent around it. `--exit-node-allow-lan-access` keeps the local LAN directly reachable. `--exit-node=` clears it. On a router, `--exit-node-forwarded-only` sends only the traffic it forwards (its LAN) through the exit node, translated to the router's mesh address, while the router's own traffic keeps using the local uplink ([deviations.md](deviations.md) #19).
- `--shields-up` refuses all incoming connections (connections this machine opens are not affected). `--advertise-tags=tag:xxx` asks the control server for tags (the server decides).
- `--ssh` runs the SSH server: peers log in as the local users the mesh's SSH policy allows, with their mesh identity, no passwords or keys. See [ssh.md](protocol/ssh.md). SSH sessions inherit the service's sandbox, so with a package install switch to the unit made for it first:

  ```bash
  sudo install -m 0644 /usr/share/flowmesh/flowmeshd-ssh.service /etc/systemd/system/flowmeshd.service
  sudo systemctl daemon-reload && sudo systemctl restart flowmeshd
  ```
- `--operator=<user>` lets that local user change settings and use `serve` without sudo.

Common commands:

| Command | What it does |
|---|---|
| `flowmesh status` | Show the state; exit code 0 only while Running |
| `flowmesh status --json` | Machine-readable state (fields compatible with the official client) |
| `sudo flowmesh down` | Disconnect (login and settings are kept) |
| `sudo flowmesh up` | Reconnect; when settings are not at their defaults, repeat all of them or add `--reset` |
| `sudo flowmesh set --accept-routes=false` | Change only the settings given |
| `sudo flowmesh logout` | Log this node out and reset every setting to its default; needs the control server |
| `flowmesh ip` | This node's mesh addresses |
| `flowmesh ping <name or IP>` | Path to a node (direct address or relay) and latency; up to 10 pings, stops once direct |
| `flowmesh whois <IP>` | Which node and user an address belongs to, and the capabilities it was granted |
| `flowmesh netcheck` | Relay latencies and NAT behavior as seen from this machine |
| `flowmesh exit-node list` | The exit nodes this node may use |
| `flowmesh dns status` / `flowmesh dns query <name>` | The DNS configuration in effect / ask the built-in resolver |
| `flowmesh serve …` | Share a local web server, files, text or a TCP port with the mesh, see [serve.md](protocol/serve.md) |
| `flowmesh ssh <user>@<node>` / `flowmesh nc <node> <port>` | Connect to a node's SSH server / open a raw TCP connection |
| `flowmesh metrics` | Prometheus metrics (names compatible with the official client) |
| `flowmesh debug prefs` | Show the current settings |
| `flowmesh bugreport` | Write a redacted diagnostic bundle to the current directory (local file only, never uploaded); you decide whether to send it |

Reading the state needs no root; changing anything needs root or the operator.

## 4. DNS

With `--accept-dns` (the default) `flowmeshd` points `/etc/resolv.conf` at `100.100.100.100`, keeps the original in `/var/lib/flowmesh/resolv.conf.backup`, and restores it when the service stops.

If `/etc/resolv.conf` is a symbolic link (managed by systemd-resolved, resolvconf or NetworkManager), `flowmeshd` **does not change it** and says so in the Health of `flowmesh status`; mesh names can still be looked up at `100.100.100.100`. Use `--accept-dns=false` in that case.

## 5. Files and permissions

| Path | Contents |
|---|---|
| `/var/lib/flowmesh/node.json` | Machine and node keys (0600) |
| `/var/lib/flowmesh/prefs.json` | Settings and login state (0600) |
| `/var/lib/flowmesh/resolv.conf.backup` | The original resolv.conf while DNS is taken over |
| `/var/run/flowmesh/flowmeshd.sock` | Local API (every local user may read the state; changes need root or the operator) |

The systemd unit runs as root but keeps only `CAP_NET_ADMIN` and `CAP_NET_RAW`, and the file system is read-only apart from the directories above and `/etc/resolv.conf` (`systemd-analyze security flowmeshd` scores 2.4). The SSH server needs `flowmeshd-ssh.service` instead, which has no sandbox (section 3).

## 6. Uninstall

```bash
sudo flowmesh logout
sudo systemctl disable --now flowmeshd
sudo rm /usr/sbin/flowmeshd /usr/bin/flowmesh /etc/systemd/system/flowmeshd.service
sudo rm -r /var/lib/flowmesh
```

## 7. Not supported

- Automatic exit node choice (`--exit-node=auto:any`): needs a recommendation from the control server.
- App connectors (`--advertise-connector`): need per-domain routing configuration from the control server, which current control servers do not send.
- HTTPS serving and Funnel: need certificates from the control server ([deviations](deviations.md) #16).
