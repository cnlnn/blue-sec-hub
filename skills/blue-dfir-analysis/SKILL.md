---
name: blue-dfir-analysis
description: 对磁盘镜像、内存转储、Windows Event Log、注册表、文件系统、容器镜像、云审计日志、PCAP 和主机采集包做数字取证与事件证据提取。用于证据保全、时间线构建、进程/身份/网络/文件关联、持久化和横向痕迹验证，以及向攻击路径还原提供可引用证据。
---

# DFIR Analysis

## Workflow

1. 记录证据来源、采集方式、时间、时区、哈希、镜像/快照状态和工具版本；原件只读，派生物单独保存。
2. 先建立全局时间线，再围绕告警时间扩展窗口；统一处理 UTC、本地时区、时钟漂移和日志延迟。
3. 按证据类型提取：
   - 主机：进程、登录、服务、任务、启动项、文件、注册表、命令历史和网络连接。
   - 内存：进程树、注入、模块、句柄、凭据痕迹、套接字和可疑内存区。
   - 网络：先提取会话与主机时间关联，深度协议和流重组转 `blue-network-traffic-analysis`。
   - 容器/云：镜像层、运行时事件、身份调用、控制面和数据面操作。
4. 使用文件哈希、时间、身份、会话、进程父子关系和对象 ID 连接证据，不用单个 IOC 自动证明因果。
5. 将每项结论标记为 `observed`、`correlated`、`inferred`、`hypothesis` 或 `rejected`。
6. 样本转 `blue-malware-analysis`，整体攻击链转 `blue-incident-reconstruction`，争议结论转 `blue-evidence-validation`。
7. 使用 `blue-security-knowledge` 检索 DFIR、Volatility、PCAP、流量和平台专项资料。

## Output

输出证据清单、规范化时间线、主机/身份/网络/文件关系、已确认行为、推断路径、证据缺口、处置建议和可复核查询或脚本。
