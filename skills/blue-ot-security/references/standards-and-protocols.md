# OT Standards And Protocol Triage

## Source Priority

1. 厂商安全公告、版本说明和设备手册：确认型号、固件、模块和配置前提。
2. [CISA ICS Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)：交叉核对受影响产品、CVSS、缓解措施和厂商链接。
3. [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)：组织已观察到的对手行为，不用于证明漏洞存在。
4. [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final)：OT 架构、风险和控制基线。
5. [ISA/IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)：IACS 生命周期、Zone/Conduit、系统和组件安全要求。

以上资料可能更新；任务涉及当前漏洞、版本或控制编号时应在线核对。

## Passive Protocol Triage

| Protocol | Common transport | First-pass evidence |
|---|---|---|
| Modbus/TCP | TCP/502 | Unit ID、功能码、地址范围、读写、异常响应 |
| S7comm/S7comm Plus | TCP/102 | Setup、Job/Ack、块操作、下载/上传、会话角色 |
| EtherNet/IP CIP | TCP/UDP 44818, UDP/2222 | Session、Class/Instance/Attribute、显式消息、I/O 周期 |
| OPC UA | TCP/4840 | Endpoint、SecurityPolicy、证书、Session、Node、读写与方法调用 |
| DNP3 | TCP/UDP/20000 | Link 地址、功能码、对象组、控制操作、时间与事件 |
| IEC 60870-5-104 | TCP/2404 | Type ID、Cause of Transmission、Common Address、遥控/遥信 |
| BACnet/IP | UDP/47808 | Device/Object、Who-Is/I-Am、Read/WriteProperty、BVLL |
| IEC 61850 | TCP/102 plus Ethernet GOOSE/SV | MMS 对象、报告、控制服务、GOOSE 状态与序号 |
| PROFINET | Ethernet plus DCE/RPC | DCP 识别/配置、设备关系、周期实时通信 |

端口仅用于候选识别。使用协议解析、设备指纹、通信关系和配置资料共同确认。

## Stop Conditions

- 过程值、控制模式、设备状态或链路质量出现非预期变化。
- 控制器/HMI/网关响应时间或错误率明显偏离基线。
- 测试请求可能触发写入、程序传输、固件更新、重启、时间修改或安全功能变化。
- 无法确认目标是仿真/测试环境或无法执行既定回滚。
