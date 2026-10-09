# 黑盒观测样本

每个子目录对应一次采集，并附有 `manifest.json`，记录所用版本、时间和结论。
基线样本由 `lab/scripts/capture.sh` 生成，生成时已用 `lab/scripts/redact.py` 脱敏：私钥和预授权 key 都替换成了 `<redacted>`，剩下的密钥只在实验环境中有效。

这些样本是 `docs/protocol/` 中各项协议事实的出处，引用格式为 `OBS-<目录名>/<文件名>`。

注意：`*-netmap.json`、`*-prefs.json`、`*-status.json` 是官方客户端的**内部视图**，并不是线上传输格式。
线上传输格式的样本从 M2 开始，由 flowmesh 探测程序记录原始报文得到。
