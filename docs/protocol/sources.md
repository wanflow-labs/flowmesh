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
