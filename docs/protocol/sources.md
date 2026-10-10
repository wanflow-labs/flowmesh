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
