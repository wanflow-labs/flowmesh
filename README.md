# FlowMesh

**Wanflow FlowMesh 的 Linux 客户端：更快、更轻。** 开源，Rust 编写。

[English](README.en.md) · [官网](https://www.wanflow.com) · [下载万联客户端](https://www.wanflow.com/downloads) · [安装 FlowMesh](docs/install.zh-CN.md)

FlowMesh 把你的 Linux 服务器、网关和路由器接入 Wanflow FlowMesh：总部、分支、云服务器、笔记本和手机，无论身在何处，都在同一张加密的私有网络里。网络条件允许时设备之间直接互连，不允许时自动经万联的中继转发。不需要开放端口，也不需要自建 VPN 网关。

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

## 快速开始

1. **创建组网。** Wanflow FlowMesh 提供永久免费的免费版。在 [wanflow.com](https://www.wanflow.com) 注册，控制台会给出组网地址和接入密钥。
2. **在每台 Linux 机器上安装并加入**：控制台「添加设备 → Linux 服务器」会生成一条命令，复制到服务器上运行即可。手动安装也只要一行（[更多方式](docs/install.zh-CN.md)）：

   ```bash
   curl -fsSL https://github.com/wanflow-labs/flowmesh/releases/latest/download/install.sh | sh -s -- --login-server=<你的组网地址> --auth-key=<密钥>
   ```

3. **添加其他设备：** 下载万联客户端，支持 [macOS、Windows、iOS 和 Android](https://www.wanflow.com/downloads)。之后组网内的每台设备都可以按名称互相访问。

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

## 同样兼容 Tailscale

FlowMesh 实现了 Tailscale 的协调协议，因此也能加入由 [headscale](https://github.com/juanfont/headscale) 管理的网络，并与官方 Tailscale 客户端互通；命令行参数与输出遵循官方客户端（[详情](docs/protocol/cli.md)）。它是独立实现，不包含 Tailscale 或 headscale 的代码。有意为之的差异列在 [deviations.md](docs/deviations.md)。

## 关于 Wanflow

万联云网关 Wanflow 提供全新的站点互联组网服务。了解更多请访问 [wanflow.com](https://www.wanflow.com)。

## 开发

    make check      # fmt + clippy + test + deny + 相似度扫描
    make lab-up     # 启动 Docker 中的本地互操作实验环境（见 lab/README.md）
    make release    # 在固定版本的容器中做可复现发布构建

协议行为通过在实验环境中观察真实客户端得出，从不复制代码；观察记录在 [docs/protocol](docs/protocol)。欢迎贡献，见 [CONTRIBUTING.md](CONTRIBUTING.md)。

"Tailscale" 是 Tailscale Inc. 的商标，"WireGuard" 是 Jason A. Donenfeld 的注册商标；二者均与本项目无关，也未为本项目背书。
