# 控制通道

状态说明：
- **已观测**：已由黑盒样本直接确认。
- **已互通**：按既有了解实现，flowmesh 与 headscale 实际互通成功，可作为该事实成立的证据。
- **待验证**：尚未确认。

## 1. 获取服务端公钥

| 事实 | 状态 | 出处 |
|---|---|---|
| `GET /key?v=<能力版本>`；官方 1.94.2 发送 `v=131` | 已观测 | OBS-20261010-control-handshake/ts1-register.pcap |
| 响应 JSON 包含 `legacyPublicKey`、`publicKey`，值为 `mkey:` 加 64 位十六进制；headscale 0.26 的 `legacyPublicKey` 全为零 | 已观测 | OBS-20261010-control-handshake/key-response.json |

## 2. 协议升级

| 事实 | 状态 | 出处 |
|---|---|---|
| `POST /ts2021 HTTP/1.1`，请求头 `Connection: upgrade`、`Upgrade: tailscale-control-protocol`、`X-Tailscale-Handshake: <base64>`、`Content-Length: 0` | 已观测 | OBS-20261010-control-handshake/framing-summary.json |
| 服务端回 `101 Switching Protocols`，之后同一连接上双向传输二进制帧 | 已观测 | 同上 |
| 官方客户端只在 80 端口上使用明文；flowmesh 对 `http://` 的任何端口都使用明文（偏差清单 #2），实测 18080 端口可以正常工作 | 已观测 / 已互通 | OBS-20261010-official-http-control；OBS-20261010-flowmesh-probe |
| 官方客户端一旦 Noise 连接失败（例如服务端重启），会转入"强制 443 TLS"模式，此后无法再用明文 80 端口重连，只能重启客户端。flowmesh 不继承这一行为 | 已观测 | lab 日志 2026-10-09T23:21:45Z（见 lab/README.md） |

## 3. 帧格式

帧头 3 字节：1 字节类型 + 2 字节大端长度，后接载荷。

| 类型 | 方向 | 载荷 | 状态 | 出处 |
|---|---|---|---|---|
| 1 发起 | 客户端，放在 `X-Tailscale-Handshake` 头中 | 帧前另加 2 字节大端协议版本（= 能力版本 131）；载荷 96 字节 | 已观测 | framing-summary.json |
| 2 响应 | 服务端，101 之后的第一帧 | 48 字节 | 已观测 | 同上 |
| 4 记录 | 双向 | 密文（明文 + 16 字节标签） | 已观测 | 同上 |

## 4. 握手与记录层

| 事实 | 状态 | 出处 |
|---|---|---|
| Noise `IK`，`25519`、`ChaChaPoly`、`BLAKE2s`；发起 96 = 32 + 48 + 16，响应 48 = 32 + 16 | 已观测（长度）/ 已互通（算法） | framing-summary.json；OBS-20261010-flowmesh-probe |
| 发起方静态密钥是 machine key，响应方静态公钥是 §1 中的 `publicKey` | 已互通 | OBS-20261010-flowmesh-probe |
| prologue 为 `Tailscale Control Protocol v<版本>` | 已互通 | 同上（prologue 错误时握手必然失败） |
| 记录层密钥取自 Noise split（发起方：第一把用于发送，第二把用于接收），算法 ChaCha20-Poly1305 | 已互通 | 同上 |
| **记录层 nonce = 4 字节零 + 8 字节大端计数器**，与 Noise 规范的小端不同 | 已观测 | 按 Noise 规范使用小端时，服务端连续发来的第 2 条记录解密失败（nonce 0 的两种编码相同，从 1 开始不同）；改成大端后互通成功 |
| 服务端先发前置载荷：5 字节魔数 `ff ff ff 54 53` + 4 字节大端长度 + JSON；明文长度依次为 5、4、95 字节；JSON 只有一个键 `nodeKeyChallenge` | 已观测 | framing-summary.json（长度）；OBS-20261010-flowmesh-probe/early.json |

## 5. 加密通道之上（HTTP/2）

| 事实 | 状态 | 出处 |
|---|---|---|
| 加密通道上运行 HTTP/2，客户端直接发连接前言 | 已互通 | OBS-20261010-flowmesh-probe |
| `POST /machine/register`：请求见 register-request.json；响应键为 `AuthURL`、`Error`、`Login`、`MachineAuthorized`、`NodeKeyExpired`、`NodeKeySignature`、`User`。**用户名在 `Login.LoginName` 中**，`User` 里没有 | 已观测 | register-response.json |
| `POST /machine/map`（`Stream: true`）：响应为连续消息，每条前缀 4 字节小端长度；请求 `Compress: "zstd"` 时消息体经 zstd 压缩 | 已互通 | map-0000.json … map-0004.json |
| 首条消息包含 `Node`、`Peers`（完整列表）、`DERPMap`、`DNSConfig`、`PacketFilters`、`UserProfiles`、`Domain`、`Debug`、`CollectServices`、`ControlTime` | 已观测 | map-0000.json |
| 后续消息是增量：`PeersChangedPatch`（如 `{"NodeID":3,"Online":true}`）、`PeersChanged`、`DERPMap`、`DNSConfig`、`Node` 等 | 已观测 | map-0001.json … map-0004.json |
| 对端节点同时带有 `HomeDERP`（整数区域号）和旧式 `DERP`（`127.3.3.40:<区域号>`）；尚无 home 时自身节点的 `DERP` 为 `127.3.3.40:0` | 已观测 | map-0000.json |
| headscale 发送的是 `PacketFilters`（`{"base":[...]}`），不发送 `PacketFilter`。`base` 组中除 ACL 规则外，还有 WanFlow control server 无条件追加的 peer relay `CapGrant` 规则 | 已观测 | map-0000.json |

## 6. 留待后续里程碑

| 问题 | 里程碑 |
|---|---|
| `PacketFilters` 的跨消息合并语义：整体替换还是逐键更新，null 的含义 | M3 |
| `DNSConfig` 各字段的应用语义（Routes 的空列表、FallbackResolvers 等） | M6 |
| `nodeKeyChallenge` 的用途 | M7（官方客户端在什么情况下使用它，需要差分观测） |

## 7. 已观测但尚未建模的字段

`Debug`（headscale 发送 `{"DisableLogTail":true}`）、`CollectServices`、`UserProfiles[].ProfilePicURL`、`Node.Hostinfo` 中的 `NetInfo`、`Services`、`GoArch` 等、`RegisterResponse.NodeKeySignature`。宽容解析会忽略这些字段；如果后续功能需要，再补建模和测试。

## 8. Node key expiry and the stream lifecycle

Source: OBS-20261010-key-expiry (`lab/scripts/fault_key_expiry.sh`; map messages tapped with `flowmesh-dev --tap-dir`) and OBS-20261010-control-outage (`lab/scripts/fault_control.sh`).

- **Expiry is pushed, not enforced by closing the stream.** After `headscale nodes expire`, the node receives a map message with a full `Node` whose `KeyExpiry` is in the past (with `ControlTime` alongside); the stream stays open and further messages keep arriving. The official client switches to `NeedsLogin` on that message (Health empty, no `AuthURL`). flowmesh does the same and puts `node key expired` in Health (design §7.2 asks for the reason).
- Expiry is judged against the message's `ControlTime` (server clock) when present, otherwise the local clock. The zero time `0001-01-01T00:00:00Z` means "never expires".
- **An expired key cannot be renewed.** Registering again with the same node key and an auth key is accepted (`MachineAuthorized`) but the node stays expired, with `NodeKeyExpired: true` in the register response. Registering a **new** node key with `OldNodeKey` set to the expired one (same machine key, same auth key) moves the node to the new key: it keeps its node ID and addresses.
- **Control server restart closes the stream** (EOF). The client must reopen it on a new Noise connection; the first message after reopening is a full netmap. Tunnels are unaffected meanwhile (0% loss over a 15 s outage).
- **Expired peers** stay in the netmap with `KeyExpiry` in the past. The official client lists them (`"Expired": true` in `status --json`) and refuses to ping them (`peer's node key has expired`, exit 1). flowmesh does the same and also leaves them out of WireGuard and path selection. Limitation: a key that reaches its expiry time without any new map message takes effect at the next message; `headscale nodes expire` always pushes one.
