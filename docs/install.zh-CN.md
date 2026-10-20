# 安装与运行（Linux + systemd）

[English](install.md)

## 1. 构建

```bash
cargo build --release -p flowmesh-daemon -p flowmesh-cli
```

产物为 `target/release/flowmeshd`（守护进程）和 `target/release/flowmesh`（命令行）。

存储空间紧张的设备（如路由器）可以不编入 SSH 服务端，`flowmeshd` 约小 2 MB：

```bash
cargo build --release -p flowmesh-daemon -p flowmesh-cli --no-default-features
```

这样构建的 `flowmeshd` 会拒绝 `--ssh`（`this flowmeshd was built without SSH support`），其余功能不变；`flowmesh ssh` / `flowmesh nc` 客户端命令用的是系统自带的 `ssh`，两种构建都有。

## 2. 安装

### 一条命令（推荐）

```bash
curl -fsSL https://github.com/wanflow-labs/flowmesh/releases/latest/download/install.sh | sh
```

脚本会按系统自动选择 deb、rpm 安装包或静态二进制（x86_64 或 aarch64；Debian/Ubuntu、RHEL/Rocky/Alma/Oracle/Fedora、openSUSE、Alpine、Arch 等），按发布的 `SHA256SUMS` 校验下载内容，缺少 iproute2 时自动安装，并启动服务（systemd 或 OpenRC）。再运行一次即升级。带上参数可同时加入组网：

```bash
curl -fsSL https://github.com/wanflow-labs/flowmesh/releases/latest/download/install.sh | \
  sh -s -- --login-server=<你的组网地址> --auth-key=<密钥> [--hostname=名称] [--advertise-exit-node] [--ssh]
```

`--version=X.Y.Z` 指定版本，`--mirror=URL` 从镜像下载（`URL/latest/…`、`URL/vX.Y.Z/…`），`--uninstall` 卸载。万联控制台会为每个组网生成这条命令。

### OpenWrt 路由器

支持 OpenWrt 21.02 到 25.12，架构为 x86_64、aarch64 和带 VFP 的 armv7（暂不支持 MIPS）。先在路由器上添加 FlowMesh 软件源：

```sh
wget -qO- https://dl.wanflow.com/openwrt/add-feed.sh | sh
```

脚本会识别路由器的架构和包管理器，导入软件源的签名公钥，并写入源配置（opkg：`/etc/opkg/customfeeds.conf`；apk：`/etc/apk/repositories.d/flowmesh.list`）。重复运行不会重复添加；架构不受支持时会直接报错退出。软件源的索引带签名（opkg 用 usign，apk 用 apk 签名），签名不对的索引和与索引不符的安装包都会被拒绝，安装时不需要 `--force-*` 或 `--allow-untrusted`。软件源只提供最新版本。

然后安装 LuCI 界面（会一并安装 `flowmesh`）：

```sh
opkg update && opkg install luci-app-flowmesh    # OpenWrt 21.02 到 24.10
apk update && apk add luci-app-flowmesh          # OpenWrt 25.12 及以后
```

只想用命令行时，可以只装 `flowmesh`。

加入组网：在 LuCI 打开「服务 → FlowMesh」，在万联控制台为组网添加设备，把控制台给出的 Linux 安装命令粘贴进去，或者手动填写组网地址和接入密钥，再填设备名，点「接入」。之后可以在同一页面开关「共享本地局域网」「作为出口节点」等设置；设置保存在 `/etc/config/flowmesh`，节点身份保存在 `/etc/flowmesh/`，两者都会在系统升级（sysupgrade）时保留。安装时会添加一个名为 `flowmesh` 的防火墙区域（设备 `flowmesh0`，与 `lan` 双向转发），卸载时删除。

升级：`opkg update && opkg upgrade flowmesh luci-app-flowmesh`（apk：`apk update && apk upgrade`）。卸载：`opkg remove luci-app-flowmesh flowmesh`（apk：`apk del luci-app-flowmesh flowmesh`），`/etc/flowmesh/` 里的节点身份会保留，彻底清除需手动删除。

### 用安装包

Debian / Ubuntu：

```bash
sudo dpkg -i flowmesh_<版本>_amd64.deb      # ARM 机器用 arm64
sudo systemctl enable --now flowmeshd
```

RHEL / Rocky / Alma：

```bash
sudo rpm -i flowmesh-<版本>-1.x86_64.rpm    # ARM 机器用 aarch64
sudo systemctl enable --now flowmeshd
```

安装包只安装文件，不会自动启用服务；卸载（`dpkg -r flowmesh` / `rpm -e flowmesh`）会先停止服务，但保留 `/var/lib/flowmesh` 里的节点身份，彻底清除需手动删除该目录。二进制为静态链接，唯一的外部依赖是 iproute2（`ip` 命令），安装包已声明该依赖。每个发布都附带 `SHA256SUMS`，可按 [可复现构建](reproducible-builds.md) 自行重建核对。

### 从源码构建

```bash
sudo install -m 0755 target/release/flowmeshd /usr/sbin/flowmeshd
sudo install -m 0755 target/release/flowmesh /usr/bin/flowmesh
sudo install -m 0644 packaging/systemd/flowmeshd.service /etc/systemd/system/flowmeshd.service
sudo systemctl daemon-reload
sudo systemctl enable --now flowmeshd
```

## 3. 加入组网

FlowMesh **没有默认控制服务器**，第一次 `up` 必须给出 `--login-server`：

```bash
sudo flowmesh up --login-server=http://<控制服务器地址>:<端口> --auth-key=file:/root/flowmesh.key
```

- 控制地址可以是 `http://`（任何端口都直接使用明文，不会改走 443；控制连接本身由 Noise 协议加密）或 `https://`（默认 443 端口，先建立 TLS，按系统根证书校验服务器证书；自签证书可用环境变量 `SSL_CERT_FILE=<CA 文件>` 指定）。

- `--auth-key` 可以直接写密钥，也可以写 `file:<路径>` 从文件读取（避免密钥出现在 shell 历史和进程列表里）。密钥只用于注册，不会写入磁盘。
- `up` 会一直等到网络进入 Running（退出码 0）；控制服务器拒绝时退出码为 1，并打印登录地址（如果服务器给了）。可以用 `--timeout=30s` 限制等待时间。
- 其他常用参数：`--hostname=<名称>`、`--accept-dns=false`（不接管系统 DNS）、`--accept-routes`（接受其他节点通告的子网路由）。
- 作为子网路由器：`--advertise-routes=192.168.1.0/24`（多个用逗号分隔），控制服务器上批准该路由后，其他节点加 `--accept-routes` 即可访问该网段。需要内核开启转发（`sysctl -w net.ipv4.ip_forward=1`，IPv6 为 `net.ipv6.conf.all.forwarding=1`；FlowMesh 不会替你改，未开启时 `up` 会给出警告）。默认对进入该网段的流量做地址伪装（SNAT），网段内主机看到的来源是路由器；`--snat-subnet-routes=false` 可关闭，此时网段内主机需要有回到 `100.64.0.0/10` 的路由。转发规则写入系统的 `iptables`（没有时用 `nft`），`down` 或退出时自动撤除。
- 作为出口节点：`--advertise-exit-node`（同样需要开启转发，并在控制服务器上批准 `0.0.0.0/0,::/0`）。出口节点只转发到公网，本机所在的局域网和私网地址不经出口节点开放（需要的话另外以子网路由宣告）。`--stateful-filtering` 可阻止从外部新建到组网内的连接。
- 使用出口节点：`--exit-node=<IP 或节点名>`，此后全部上网流量（包括 DNS）经出口节点；出口节点离线时上网流量被丢弃而不会绕开。需要直接访问本机局域网时加 `--exit-node-allow-lan-access`。`--exit-node=` 取消。
- `--shields-up`：拒绝所有入站连接（本机主动发起的连接不受影响）。`--advertise-tags=tag:xxx`：向控制服务器申请标签（是否授予由服务器决定）。
- `--ssh`：开启 SSH 服务端，组网内的对端按组网的 SSH 策略以本机用户身份登录，凭组网身份认证，不需要密码或密钥。详见 [ssh.md](protocol/ssh.md)。SSH 会话会继承服务的沙箱，所以用安装包时先换成专门为它准备的单元：

  ```bash
  sudo install -m 0644 /usr/share/flowmesh/flowmeshd-ssh.service /etc/systemd/system/flowmeshd.service
  sudo systemctl daemon-reload && sudo systemctl restart flowmeshd
  ```
- `--operator=<用户>`：允许该本地用户不用 sudo 修改设置、使用 `serve`。

常用命令：

| 命令 | 作用 |
|---|---|
| `flowmesh status` | 查看状态；只有 Running 时退出码为 0 |
| `flowmesh status --json` | 机器可读的状态（字段与官方客户端兼容） |
| `sudo flowmesh down` | 断开（保留登录与设置） |
| `sudo flowmesh up` | 重新连接；若当前有非默认设置，需要把它们全部再写一遍，或加 `--reset` |
| `sudo flowmesh set --accept-routes=false` | 只修改给出的设置 |
| `sudo flowmesh logout` | 注销本节点并把所有设置恢复为默认；需要能连上控制服务器 |
| `flowmesh ip` | 本节点的组网地址 |
| `flowmesh ping <主机名或IP>` | 探测到某个节点的路径（直连地址或中继）与延迟；默认最多 10 次，建立直连即停止 |
| `flowmesh whois <IP>` | 查看某个地址属于哪个节点、哪个用户，以及它被授予的能力 |
| `flowmesh netcheck` | 从本机看到的各中继延迟与 NAT 特性 |
| `flowmesh exit-node list` | 本节点可用的出口节点 |
| `flowmesh dns status` / `flowmesh dns query <名称>` | 当前生效的 DNS 配置 / 向内置解析器查询 |
| `flowmesh serve …` | 把本机的网页服务、文件、文本或 TCP 端口共享到组网，详见 [serve.md](protocol/serve.md) |
| `flowmesh ssh <用户>@<节点>` / `flowmesh nc <节点> <端口>` | 连接某节点的 SSH 服务端 / 建立原始 TCP 连接 |
| `flowmesh metrics` | Prometheus 指标（名称与官方客户端兼容） |
| `flowmesh debug prefs` | 查看当前设置 |
| `flowmesh bugreport` | 在当前目录生成脱敏诊断包（只写本地文件，不会上传），由你决定是否发给技术支持 |

查看状态不需要 root；任何修改都需要 root 或 operator。

## 4. DNS

`--accept-dns`（默认开启）时，`flowmeshd` 会把 `/etc/resolv.conf` 改为指向 `100.100.100.100`，原文件备份在 `/var/lib/flowmesh/resolv.conf.backup`，停止服务时自动还原。

如果 `/etc/resolv.conf` 是符号链接（由 systemd-resolved、resolvconf 或 NetworkManager 管理），`flowmeshd` **不会修改它**，并在 `flowmesh status` 的 Health 中说明；组网内的名称仍可通过 `100.100.100.100` 查询。这种情况下建议使用 `--accept-dns=false`。

## 5. 文件与权限

| 路径 | 内容 |
|---|---|
| `/var/lib/flowmesh/node.json` | 机器密钥与节点密钥（0600） |
| `/var/lib/flowmesh/prefs.json` | 设置与登录状态（0600） |
| `/var/lib/flowmesh/resolv.conf.backup` | 接管 DNS 期间的原 resolv.conf |
| `/var/run/flowmesh/flowmeshd.sock` | 本地 API（所有本地用户可读状态，修改需 root 或 operator） |

systemd 单元以 root 运行，但只保留 `CAP_NET_ADMIN` 与 `CAP_NET_RAW`，文件系统除上述目录和 `/etc/resolv.conf` 外全部只读（`systemd-analyze security flowmeshd` 评分 2.4）。SSH 服务端需要改用不带沙箱的 `flowmeshd-ssh.service`（见第 3 节）。

## 6. 卸载

```bash
sudo flowmesh logout
sudo systemctl disable --now flowmeshd
sudo rm /usr/sbin/flowmeshd /usr/bin/flowmesh /etc/systemd/system/flowmeshd.service
sudo rm -r /var/lib/flowmesh
```

## 7. 暂不支持

- 自动选择出口节点（`--exit-node=auto:any`）：需要控制服务器推荐，暂不支持。
- 应用连接器（`--advertise-connector`）：需要控制服务器下发按域名路由的配置，当前控制服务器不支持。
- HTTPS 形式的 serve 与 Funnel：需要控制服务器签发证书（[偏差清单](deviations.md) #16）。
