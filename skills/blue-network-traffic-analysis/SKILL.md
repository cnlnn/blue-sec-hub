---
name: blue-network-traffic-analysis
description: 对 PCAP/PCAPNG、单个数据包、十六进制报文、TShark/Zeek/Suricata 输出、NetFlow 和代理抓包做网络流量分析。用于协议识别、会话重组、HTTP/DNS/TLS/邮件/文件传输分析、异常行为与信标发现、载荷和 IOC 提取、横向与外联路径验证，并向护网应急和攻击路径还原提供可引用证据。
---

# Network Traffic Analysis

## Workflow

1. 保存原始抓包，记录 SHA-256、采集点、接口、时间范围、时区、链路类型、SnapLen、过滤条件和可能的丢包；派生文件单独保存。
2. 先做全局画像：包数、持续时间、端点、会话、协议、端口、字节量、DNS、TLS SNI/证书、HTTP Host/URI 和高频通信对。
3. 围绕告警、IOC 或异常时间建立精确显示过滤器，重组 TCP/UDP 流并导出相关对象；大型 PCAP 先按时间、主机或会话切片，不把全包一次性载入上下文。
4. 按协议验证请求与响应、方向、状态、序列、重传、分片、编码、压缩和载荷。单个端口或工具自动识别只能作为协议候选。
5. 分析常见异常：
   - HTTP/API：扫描、利用请求、WebShell/C2、上传下载、异常 UA/Cookie 和响应差异。
   - DNS：异常域名、快速切换、长标签、TXT、隧道和解析时间关系。
   - TLS：SNI、证书、ALPN、版本和会话元数据；没有密钥时不得声称看到了加密正文。
   - 横向/内网：SMB、RDP、WinRM、SSH、数据库、目录服务和远程管理会话。
   - 外联/C2：周期、抖动、包长、上下行比例、域名/IP 切换和协议不一致。
6. 提取文件、哈希、域名、IP、URL、证书和载荷，样本交 `blue-malware-analysis`，IOC/基础设施交 `blue-threat-intel-analysis`。
7. 把确认的会话边、时间和身份线索交 `blue-incident-reconstruction`；工业协议同时使用 `blue-ot-security`。
8. 使用 `blue-security-knowledge` 检索 traffic-analysis、network-forensics、协议和工具专项资料。

## Evidence Levels

- `packet-observed`：报文在采集点可见。
- `session-established`：握手或双向状态支持会话建立。
- `request-delivered`：请求已到达对端协议栈或应用。
- `action-accepted`：响应或后续状态证明动作被接受。
- `impact-confirmed`：主机、应用或业务证据确认产生影响。

不得从单个请求包直接推断利用成功。

## Output

输出抓包身份、采集限制、时间线、端点/会话表、关键过滤器、重组流、提取物及哈希、IOC、协议证据、攻击路径边、已排除解释和下一项高价值取证动作。
