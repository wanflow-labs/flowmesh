# 出处索引

| 编号 | 类型 | 内容 |
|---|---|---|
| PUB-1 | 规范 | The Noise Protocol Framework, revision 34 — https://noiseprotocol.org/noise.html |
| PUB-2 | 论文 | WireGuard: Next Generation Kernel Network Tunnel — https://www.wireguard.com/papers/wireguard.pdf |
| PUB-3 | RFC | RFC 5389 Session Traversal Utilities for NAT (STUN) |
| PUB-4 | 官方博客 | How NAT traversal works — https://tailscale.com/blog/how-nat-traversal-works |
| PUB-5 | 官方知识库 | DERP servers — https://tailscale.com/kb/1232/derp-servers |
| OBS-20261010-baseline | 观测 | 实验环境基线：两个官方 v1.94.2 客户端经实验环境控制服务器入网后的状态、偏好、网络地图，以及 headscale 侧的节点和策略（已脱敏） |
| OBS-20261010-official-http-control | 观测 | 官方 v1.94.2 客户端在 `http://` 控制地址使用非 80 端口时强制改用 TLS 443；解析控制主机名时还会向 `*.tailscale.com` 发起 bootstrap DNS 查询 |
| OBS-20261010-peer-relay-official | 观测 | 官方 v1.94.2 客户端 tsr 作 peer relay 服务器（`--relay-server-port=40000`），ts1↔ts2 的直连 UDP 被丢弃后，ts1 经 `peer-relay(172.29.0.23:40000:vni:1)` 到达 ts2；`status --json` 的 `PeerRelay` 为同一字符串 |
| OBS-20261010-probe-disco-mode | 观测 | flowmesh-probe disco 模式经 DERP 向 ts1 发 Ping 并收到 Pong；只发流式 MapRequest 时 ts1 看不到探针的 DiscoKey；DERP 只投递给连在同一中继上的客户端（否则回 PeerGone） |
| OBS-20261010-peer-relay-alloc-request | 观测 | 官方客户端发给候选中继服务器的分配请求 0x08：正文、重发与轮次、发送条件 |
| OBS-20261010-peer-relay-alloc-response | 观测 | 中继服务器对 0x08 的回复 0x09：逐字段解码与变体实验 |
| OBS-20261010-peer-relay-forward | 观测 | 客户端把分配转给对端的 0x07 |
| OBS-20261010-peer-relay-datapath | 观测 | 中继端口抓包：Geneve 头、握手时序、数据路径 |
| OBS-20261010-peer-relay-handshake | 观测 | 以探针为客户端尝试与中继服务器握手（尚无回复） |
| OBS-20261010-peer-relay-behavior | 观测 | 中继失效与恢复、闲置、与 prefer/strict 模式的配合 |
| OBS-20261011-subnet-router-official | 观测 | 官方客户端作子网路由器（`lab/scripts/subnet_router_observe.sh`）：转发开关下的 `up` 警告、netfilter 规则（ts-forward / ts-postrouting，fwmark 0x40000）、NoSNAT 默认 false；健康信息为空 |
| OBS-20261011-exit-node-official | 观测 | 官方客户端的出口节点（提供与使用）、`--exit-node-allow-lan-access`、`--shields-up`、`--stateful-filtering`、`--advertise-tags`（`lab/scripts/exit_node_observe.sh`，经 `lab/scripts/tls_proxy.sh` 的 https 地址避开"强制 TLS"）：策略路由（规则 5210/5230/5250/5270、表 52、fwmark 0x80000/0xff0000）、允许局域网时表 52 里 `throw` 本地网段、出口节点不转发到私网/本地网段（回 TSMP reject）、有状态过滤的 conntrack 规则、标签格式校验 |
| PUB-6 | 公开标准 | RFC 8926 Geneve — https://www.rfc-editor.org/rfc/rfc8926 |
