# 偏差清单

flowmesh 所有可从外部观察到的行为，都与 Tailscale 官方客户端保持一致。本清单列出的是有意为之的偏差，清单之外的差异一律按 bug 处理（设计稿 §4.4）。

| # | 偏差 | 原因 | 依据 | 状态 |
|---|---|---|---|---|
| 1 | 所有 DERP 节点 `STUNPort=-1` 时进入 relay-only 模式：不直连，也不发 CallMeMaybe | WanFlow 的 prefer 中继模式，服务端 fork 依赖这一语义 | 设计稿 §2.1 | 待实现（M5） |
| 2 | `http://` 控制地址使用任何端口都走明文，不强制 TLS，也不回退到 443 | WanFlow 的控制地址都是 `http://ip:<高位端口>` | 官方行为：OBS-20261010-official-http-control | 待实现（M2） |
| 3 | 无遥测，无自动更新；控制端主动请求（c2n）默认全部拒绝；不向任何内置的第三方地址发起 bootstrap DNS 查询 | 零遥测承诺（设计稿 §7.4） | 官方会发起 bootstrap DNS：OBS-20261010-official-http-control | 待实现（M2/M7） |
| 4 | 支持内核 WireGuard 后端 | 性能 | 设计稿 §3.4 | v2 |
| 5 | ACL 规则解析失败时 fail-closed（如果与官方行为不同） | 安全优先 | — | 待 M3 差分确认 |
