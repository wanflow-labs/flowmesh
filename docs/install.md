# 安装与运行（Linux + systemd）

## 1. 构建

```bash
cargo build --release -p flowmesh-daemon -p flowmesh-cli
```

产物为 `target/release/flowmeshd`（守护进程）和 `target/release/flowmesh`（命令行）。

## 2. 安装

```bash
sudo install -m 0755 target/release/flowmeshd /usr/sbin/flowmeshd
sudo install -m 0755 target/release/flowmesh /usr/bin/flowmesh
sudo install -m 0644 packaging/systemd/flowmeshd.service /etc/systemd/system/flowmeshd.service
sudo systemctl daemon-reload
sudo systemctl enable --now flowmeshd
```

## 3. 加入组网

flowmesh **没有默认控制服务器**，第一次 `up` 必须给出 `--login-server`：

```bash
sudo flowmesh up --login-server=https://<你的控制服务器> --auth-key=file:/root/flowmesh.key
```

- `--auth-key` 可以直接写密钥，也可以写 `file:<路径>` 从文件读取（避免密钥出现在 shell 历史和进程列表里）。密钥只用于注册，不会写入磁盘。
- `up` 会一直等到网络进入 Running（退出码 0）；控制服务器拒绝时退出码为 1，并打印登录地址（如果服务器给了）。可以用 `--timeout=30s` 限制等待时间。
- 其他常用参数：`--hostname=<名称>`、`--accept-dns=false`（不接管系统 DNS）、`--accept-routes`（接受其他节点通告的子网路由）。

常用命令：

| 命令 | 作用 |
|---|---|
| `flowmesh status` | 查看状态；只有 Running 时退出码为 0 |
| `flowmesh status --json` | 机器可读的状态（字段与官方客户端兼容） |
| `sudo flowmesh down` | 断开（保留登录与设置） |
| `sudo flowmesh up` | 重新连接；若当前有非默认设置，需要把它们全部再写一遍，或加 `--reset` |
| `sudo flowmesh set --accept-routes=false` | 只修改给出的设置 |
| `sudo flowmesh logout` | 注销本节点并把所有设置恢复为默认；需要能连上控制服务器 |

查看状态不需要 root；任何修改都需要 root。

## 4. DNS

`--accept-dns`（默认开启）时，flowmeshd 会把 `/etc/resolv.conf` 改为指向 `100.100.100.100`，原文件备份在 `/var/lib/flowmesh/resolv.conf.backup`，停止服务时自动还原。

如果 `/etc/resolv.conf` 是符号链接（由 systemd-resolved、resolvconf 或 NetworkManager 管理），flowmeshd **不会修改它**，并在 `flowmesh status` 的 Health 中说明；组网内的名称仍可通过 `100.100.100.100` 查询。这种情况下建议使用 `--accept-dns=false`。

## 5. 文件与权限

| 路径 | 内容 |
|---|---|
| `/var/lib/flowmesh/node.json` | 机器密钥与节点密钥（0600） |
| `/var/lib/flowmesh/prefs.json` | 设置与登录状态（0600） |
| `/var/lib/flowmesh/resolv.conf.backup` | 接管 DNS 期间的原 resolv.conf |
| `/run/flowmesh/flowmeshd.sock` | 本地 API（所有本地用户可读状态，修改需 root） |

systemd 单元以 root 运行，但只保留 `CAP_NET_ADMIN` 与 `CAP_NET_RAW`，文件系统除上述目录和 `/etc/resolv.conf` 外全部只读（`systemd-analyze security flowmeshd` 评分 2.4）。

## 6. 卸载

```bash
sudo flowmesh logout
sudo systemctl disable --now flowmeshd
sudo rm /usr/sbin/flowmeshd /usr/bin/flowmesh /etc/systemd/system/flowmeshd.service
sudo rm -r /var/lib/flowmesh
```

## 7. 暂不支持

- `--advertise-routes`（作为子网路由器通告网段）：会被明确拒绝，计划在后续版本实现。
- 内核 WireGuard 后端（当前为用户态实现）：v2。
