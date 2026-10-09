# 互操作实验环境

本机 Docker 中运行 control server、自签证书的 DERP 和两个官方客户端（作为参照物），用于黑盒观测和差分测试。不连接任何生产主机。

| 服务 | 地址 |
|---|---|
| headscale | `http://headscale.lab`（172.29.0.10:80） |
| DERP | `derp.lab:443`（172.29.0.11），STUN 3478 |
| ts1 / ts2 | 172.29.0.21 / 172.29.0.22 |

    make lab-up      # 启动并让 ts1、ts2 入网（首次会构建本机架构的 headscale 镜像）
    make lab-smoke   # 冒烟测试：直连 ping、home 中继、阻断直连后改走 DERP
    make lab-capture # 采集观测样本到 fixtures/observed/
    make lab-down    # 销毁（含数据卷）

`lab/.authkey` 保存可复用的预授权 key（带 `tag:relay-enabled`，24 小时有效），已加入 .gitignore。

## 与生产环境的差异及原因

| 差异 | 原因 |
|---|---|
| headscale 监听 80 端口（生产环境为 `http://ip:<高位端口>`） | 官方客户端只在 80 端口上允许明文控制连接，其他端口一律强制 TLS（见 `fixtures/observed/20261010-official-http-control/`）。生产环境的 wanflow-mesh 打了补丁去掉这一限制，flowmesh 将以偏差清单第 2 条的形式实现同样行为。 |
| headscale 用本机架构从 `../control-server` 源码构建（`scripts/build-images.sh`） | 在 arm64 主机上模拟运行 amd64 镜像时，Noise 握手报 `chacha20poly1305: message authentication failed`。 |
| DERP 用自签证书 + `insecurefortests` | 实验环境没有公网域名。 |
