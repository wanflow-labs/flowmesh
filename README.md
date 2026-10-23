# FlowMesh

**让电脑、手机、服务器和路由器连成一张私有网络。** 万联提供全平台客户端，本仓库是面向 Linux 与 OpenWrt 的轻量开源 Rust 客户端。

[**创建免费组网 →**](https://console.wanflow.com/order/mesh/configure?tier=free&utm_source=github&utm_medium=readme&utm_campaign=flowmesh&utm_content=zh) · [万联控制台](https://console.wanflow.com/) · [全平台客户端](#全平台客户端) · [使用方法](#使用方法) · [English](README.en.md)

家里的 NAS、办公室的服务器、云主机和随身的电脑、手机，都可以通过 Wanflow FlowMesh 加入同一张加密私有网络。设备之间尽量直接互连，无法直连时自动通过万联中继转发，无需开放入站端口，也无需自建 VPN 网关。

万联提供托管控制服务和中继，通过统一后台管理设备与访问权限，让不同平台、不同地点的设备互联。

## 用它做什么

| 你的场景 | 能带来什么 |
|---|---|
| **出门访问家里的 NAS 或服务** | 通过加密私有网络远程访问文件、家庭服务和设备，无需把服务端口暴露到公网 |
| **连接办公室与云服务器** | 跨地点访问业务服务，统一管理设备与访问权限 |
| **让 OpenWrt 路由器接入组网** | 通过子网路由连接整个局域网，或将路由器作为出口节点 |

## 全平台客户端

**支持 Windows、macOS、Linux、iOS、Android 和 OpenWrt。** 电脑、手机、服务器与路由器可以加入同一个万联组网。

| 平台 | 客户端 |
|---|---|
| Windows / macOS | 万联桌面客户端 |
| iOS / Android | 万联移动客户端 |
| Linux | 本仓库的 FlowMesh 开源客户端，支持 x86_64 / aarch64 |
| OpenWrt | 本仓库的 FlowMesh 开源客户端，带 LuCI 管理界面；支持 x86_64 / aarch64 / 带 VFP 的 armv7，暂不支持 MIPS |

[下载桌面与移动客户端](https://www.wanflow.com/downloads) · [查看使用方法](#使用方法)

## 为什么选 FlowMesh

在同一张组网里与 Tailscale 1.94.2 并排实测：

| | FlowMesh | Tailscale |
|---|---|---|
| 隧道内 TCP 吞吐，发送 | **2.88 Gbit/s** | 2.39 Gbit/s |
| 隧道内 TCP 吞吐，接收 | 2.52 Gbit/s | 2.70 Gbit/s |
| 每 Gbit/s 消耗的 CPU（发送 / 接收） | **0.29 / 0.42 核** | 0.79 / 0.81 核 |
| 隧道内延迟 | **1.0 ms** | 1.6 ms |
| 守护进程内存（空闲，100 个节点） | **10 MB** | 48 MB |
| 守护进程线程数 | **9** | 14 |
| 程序体积，守护进程 + 命令行（arm64） | **9.8 MB** | 64.8 MB |

同一量级的吞吐，CPU 只要 **三分之一到一半**，内存只要 **五分之一**。资源越紧张越能体现差别：路由器、小规格云主机、边缘设备，或者 CPU 本该留给业务的服务器。构建时去掉 SSH 服务端，守护进程还能再小 2 MB。

<sub>实验环境数据，同一台繁忙主机（8 核 Apple Silicon Mac 上的 Docker，负载约 8）：两种客户端各两个节点直连，`iperf3` 每个方向 10 秒，取 4 轮中位数（单轮波动可达 ±20%；此前一次较空闲时的测量为 4.44 / 4.21 Gbit/s 对 3.71 / 3.35）。FlowMesh 的数据包处理用一个核，Tailscale 会分散到多个核，因此在空闲的多核机器上 Tailscale 能从多出的核获益更多。内存与线程数在两者加入同一个 100 节点组网后空闲时采样。Tailscale 一侧是万联构建的 Tailscale 1.94.2，数据面为未修改的上游代码。请横向比较两列，不要直接对照你自己的硬件。</sub>

## 功能

- **设备间直连的加密隧道**（WireGuard），尽量穿透 NAT；否则经万联的中继转发，包括高性能中继
- **中继模式**在万联控制台设置：能直连就直连、优先中继、或仅走中继
- 控制台统一管理的**访问控制**（ACL 与标签）；**子网路由**访问整个办公网段；**出口节点**让上网流量从指定站点出去
- **用名称代替地址**（MagicDNS），内置解析器
- **按组网身份登录的 SSH**（`--ssh`）：按策略以允许的用户登录，不用分发密钥或密码
- **把本机服务共享到组网**（`flowmesh serve`）：网页应用、文件或 TCP 端口
- **内置运维命令**：`status`、`ping`、`whois`、`netcheck`、`metrics`（Prometheus）、`bugreport`
- Debian/Ubuntu（deb）与 RHEL/Rocky/Alma（rpm）**安装包**，x86_64 与 aarch64 静态二进制，加固的 systemd 单元
- **OpenWrt 路由器**（21.02 到 25.12）：签名软件源，一行命令添加，带 LuCI 界面（[安装](docs/install.zh-CN.md#openwrt-路由器)）

## 值得信任

- **开源**，Apache-2.0。运行在你机器上的每一行代码都可以审阅。
- **零遥测。** `flowmeshd` 只连接你组网的控制服务器、它指定的中继、组网内的对端和你的 DNS 服务器。没有默认服务器，没有自动更新，不会偷偷回传任何数据。
- **可复现构建。** 发布的二进制可以由这份源码逐字节重建（[方法](docs/reproducible-builds.md)）。
- **内存安全。** Rust 编写，所有 crate 都禁止 `unsafe`。

## 使用方法

### 1. 在万联创建免费组网

打开 [**创建免费组网**](https://console.wanflow.com/order/mesh/configure?tier=free&utm_source=github&utm_medium=readme&utm_campaign=flowmesh&utm_content=zh)，注册或登录后完成创建。免费版可长期使用，当前额度和功能以创建页面为准；更多方案见 [套餐说明](https://www.wanflow.com/pricing)。

### 2. 接入第一台设备

- **Linux 服务器：** 在组网控制台选择「添加设备 → Linux 服务器」，复制生成的安装命令到服务器执行。命令包含你的组网地址和接入密钥，请勿公开分享。
- **OpenWrt 路由器：** 按 [安装说明](docs/install.zh-CN.md#openwrt-路由器) 安装 FlowMesh 和 LuCI 界面，在「服务 → FlowMesh」粘贴控制台生成的命令并接入。

需要手动安装、升级或卸载？查看 [Linux 与 OpenWrt 安装文档](docs/install.zh-CN.md)。

### 3. 添加第二台设备，确认连通

在另一台 Linux 或 OpenWrt 设备上重复接入，或下载 [macOS、Windows、iOS、Android 万联客户端](https://www.wanflow.com/downloads)，加入同一个组网。确认控制台中两台设备都已在线，然后在 Linux 设备上运行：

```bash
flowmesh status
flowmesh ping '另一台设备的组网IP'
```

将占位符替换为控制台显示的实际组网 IP。连通后，就可以用组网 IP 访问对端的 SSH、网页或其他服务；服务需要在对端监听，且组网访问策略与设备防火墙允许连接。访问路由器后面的 NAS 等设备，还需要配置并批准子网路由，见 [安装文档](docs/install.zh-CN.md#3-加入组网)。

## 协议与兼容性

FlowMesh 独立实现了 Tailscale 的协调协议，可与官方 Tailscale 客户端在同一组网内互通；命令行参数与输出的兼容范围见 [CLI 文档](docs/protocol/cli.md)，已知差异与功能限制见 [deviations.md](docs/deviations.md)。

## 关于 Wanflow

万联云网关 Wanflow 提供托管组网服务，通过统一控制台管理设备、访问策略和中继。本仓库开源的是 Linux / OpenWrt 客户端，采用 Apache-2.0 许可证；托管服务的额度和功能按所选套餐提供。

[**创建免费组网**](https://console.wanflow.com/order/mesh/configure?tier=free&utm_source=github&utm_medium=readme&utm_campaign=flowmesh&utm_content=zh) · [了解万联](https://www.wanflow.com) · [查看套餐](https://www.wanflow.com/pricing)

## 开发

    make check      # fmt + clippy + test + deny + 相似度扫描
    make lab-up     # 启动 Docker 中的本地互操作实验环境（见 lab/README.md）
    make release    # 在固定版本的容器中做可复现发布构建

协议行为通过在实验环境中观察真实客户端得出，从不复制代码；观察记录在 [docs/protocol](docs/protocol)。欢迎贡献，见 [CONTRIBUTING.md](CONTRIBUTING.md)。

"Tailscale" 是 Tailscale Inc. 的商标，"WireGuard" 是 Jason A. Donenfeld 的注册商标；二者均与本项目无关，也未为本项目背书。
