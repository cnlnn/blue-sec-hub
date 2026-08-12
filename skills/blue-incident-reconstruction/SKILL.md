---
name: blue-incident-reconstruction
description: 从攻击情报、IOC、告警、异常 HTTP 请求、访问日志、主机日志、PCAP、样本、截图或一句异常描述开始紧急排查，建立时间线、关联身份和资产、还原攻击路径并判断当前影响；适用于护网、应急响应和事后复盘。
---

# Incident Reconstruction

从用户当前拥有的任意一条信号开始，不要求先有漏洞报告或完整案件信息。

## Workflow

1. 保存原始材料并提取时间、时区、源/目的、身份、会话、URL、参数、状态码、响应大小、进程、文件和哈希。
2. 围绕首个信号扩展前后时间窗口，关联同 IP、账号、Cookie、UA、进程、文件和目标对象。
3. 建立事件时间线和资产/身份/业务对象图；攻击阶段映射只作为索引，不替代证据。
4. 对每条路径边标记 `confirmed`、`inferred`、`hypothesis` 或 `rejected`，并关联原始证据位置。
5. 同时输出快速态势和深入调查：
   - 快速态势：是否持续、当前影响、受影响资产、立即处置建议。
   - 深入调查：入口、执行、持久化、横向、目标访问、数据动作和缺口。
6. 需要复现接口或代码路径时转 `blue-vuln-retest`；流量转 `blue-network-traffic-analysis`；IOC 和基础设施关联转 `blue-threat-intel-analysis`；样本转 `blue-malware-analysis`；磁盘、内存、事件日志、注册表和主机取证转 `blue-dfir-analysis`。

不要把同一时间出现、同一 IP 或单个 IOC 命中自动解释为因果关系。
