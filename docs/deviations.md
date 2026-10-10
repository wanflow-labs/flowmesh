# 偏差清单

flowmesh 所有可从外部观察到的行为，都与 Tailscale 官方客户端保持一致。本清单列出的是有意为之的偏差，清单之外的差异一律按 bug 处理（设计稿 §4.4）。

| # | 偏差 | 原因 | 依据 | 状态 |
|---|---|---|---|---|
| 1 | prefer mode (all DERP nodes `STUNPort=-1`): never initiates direct connections, does not run STUN, does not send or accept CallMeMaybe; **still replies to UDP pings** and reports local endpoints, so LAN peers can still go P2P | WanFlow prefer relay mode, consistent with wanflow-mesh | disco.md §6, OBS-20261010-relay-modes | Implemented (M5) |
| 2 | `http://` 控制地址使用任何端口都走明文，不强制 TLS，也不回退到 443 | WanFlow 的控制地址都是 `http://ip:<高位端口>` | 官方行为：OBS-20261010-official-http-control | 待实现（M2） |
| 3 | 无遥测，无自动更新；控制端主动请求（c2n）默认全部拒绝；不向任何内置的第三方地址发起 bootstrap DNS 查询 | 零遥测承诺（设计稿 §7.4） | 官方会发起 bootstrap DNS：OBS-20261010-official-http-control | 待实现（M2/M7） |
| 4 | 支持内核 WireGuard 后端 | 性能 | 设计稿 §3.4 | v2 |
| 5 | ACL rule parse failure is fail-closed (if official behavior differs) | security first | — | pending M3 differential confirmation |
| 6 | **strict mode** (self node carries `tag:relay-strict`): no direct traffic of any kind — no reply to UDP pings, CallMeMaybe ignored. **Stricter than wanflow-mesh**: wanflow-mesh accepts the peer's CallMeMaybe under strict and goes direct | honor the product promise "always relay, no P2P" (the WanFlow backend the production configuration comment) | disco.md §6, OBS-20261010-relay-modes | Implemented (M5) |
