# 控制通道

状态说明：**已观测** = 已从黑盒样本中直接确认；**待验证** = 依据对协议的既有了解编写，需要 flowmesh 与 headscale 实际互通后才能确认（M2 验收时逐条更新）。

## 1. 获取服务端公钥

| 事实 | 状态 | 出处 |
|---|---|---|
| 客户端先发送 `GET /key?v=<能力版本>`，官方 1.94.2 发送的是 `v=131` | 已观测 | OBS-20261010-control-handshake/ts1-register.pcap |
| 响应为 JSON，包含 `legacyPublicKey` 和 `publicKey` 两个字段，值为 `mkey:` 加 64 位十六进制；headscale 0.26 的 `legacyPublicKey` 全为零 | 已观测 | OBS-20261010-control-handshake/key-response.json |

## 2. 协议升级

| 事实 | 状态 | 出处 |
|---|---|---|
| `POST /ts2021 HTTP/1.1`，请求头 `Connection: upgrade`、`Upgrade: tailscale-control-protocol`、`X-Tailscale-Handshake: <base64>`，`Content-Length: 0` | 已观测 | OBS-…/framing-summary.json |
| 服务端回 `101 Switching Protocols`，之后连接上双向传输二进制帧 | 已观测 | 同上 |
| 官方客户端只对 80 端口使用明文；flowmesh 对 `http://` 的任何端口都使用明文（偏差清单 #2） | 已观测 | OBS-20261010-official-http-control |

## 3. 帧格式

帧头 3 字节：1 字节类型 + 2 字节大端长度，后接载荷。

| 类型 | 方向 | 载荷 | 状态 | 出处 |
|---|---|---|---|---|
| 1 发起 | 客户端，放在 `X-Tailscale-Handshake` 头中 | 帧头前额外有 2 字节大端协议版本（观测值 131，与能力版本相同）；载荷 96 字节 | 已观测 | framing-summary.json `handshake_header_decoded` |
| 2 响应 | 服务端，101 之后的第一帧 | 48 字节 | 已观测 | framing-summary.json |
| 4 记录 | 双向 | 密文（明文 + 16 字节认证标签） | 已观测 | framing-summary.json |

## 4. 握手

| 事实 | 状态 | 出处 |
|---|---|---|
| Noise IK 模式，曲线 25519，ChaChaPoly，BLAKE2s。发起消息 96 = 32 字节临时公钥 + 48 字节加密静态公钥 + 16 字节空载荷标签；响应 48 = 32 + 16 | 长度已观测，算法待验证 | PUB-1；framing-summary.json |
| 发起方静态密钥是客户端的 machine key，响应方静态公钥是 §1 中的 `publicKey` | 待验证 | — |
| prologue 为 `Tailscale Control Protocol v<版本号>` | 待验证 | — |
| 服务端握手完成后先发一段"前置载荷"：5 字节魔数 + 4 字节大端长度 + JSON。观测到服务端最先发出的三条记录，明文长度依次为 5、4、95 | 长度已观测，内容待验证 | framing-summary.json |

## 5. 加密通道之上

| 事实 | 状态 |
|---|---|
| 加密通道上运行 HTTP/2（客户端直接发送连接前言） | 待验证 |
| `POST /machine/register`：注册，带预授权 key | 待验证 |
| `POST /machine/map`：长连接，响应为连续的消息，每条前缀 4 字节小端长度，可选 zstd 压缩 | 待验证 |
