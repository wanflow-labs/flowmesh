# flowmesh 协议规范

本目录用我们自己的语言，描述 flowmesh 实现的、与 Tailscale 兼容的协议。

## 规则

1. 每一条协议事实都必须标注出处，编号见 [sources.md](sources.md)：
   - `PUB-<n>`：公开文档，包括规范、论文、官方博客和知识库。
   - `OBS-<目录>/<文件>`：`fixtures/observed/` 中的黑盒观测样本。
2. 编写本规范和 flowmesh 代码时，不参考 Tailscale、headscale 及其衍生项目的源码。
3. 魔数、帧类型编号、能力版本号等互操作常量可以直接使用，但必须注明出处。

## 章节（随里程碑补充）

| 文件 | 内容 | 里程碑 |
|---|---|---|
| control.md | 控制通道握手、注册、网络地图 | M2 |
| filter.md | 过滤规则格式与判定语义 | M3 |
| derp.md | DERP 帧格式 | M4 |
| disco.md | disco 与 STUN | M5 |
