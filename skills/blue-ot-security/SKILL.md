---
name: blue-ot-security
description: 对工业控制系统和运营技术环境开展安全巡查、漏洞复测、攻击路径还原与应急分析。适用于 ICS、SCADA、DCS、PLC、RTU、HMI、工程师站、历史数据库、SIS、安全网关、工业协议 PCAP、固件、组态与厂商通告；默认从离线材料和被动证据开始，区分网络入侵证据与物理过程影响。
---

# OT Security

OT 的可用性、确定性和人身/设备安全优先于扫描覆盖率。生产环境默认只做被动采集、配置审阅和离线分析；主动测试应落在仿真、测试台或已确认维护窗口。

## Workflow

1. 保存 PCAP、拓扑、组态、PLC/HMI 工程文件、固件、日志和通告，记录哈希、采集点、时间同步、厂商、型号、固件及过程状态。
2. 建立真实的 Zone/Conduit、资产、身份和数据流图，标出 IT/OT 边界、工程访问、远程维护、历史库、SIS 及单点故障，不用端口号代替资产确认。
3. 先从流量和配置建立正常基线：通信对、周期、功能码/服务、读写比例、工程下载、模式切换、时间同步和异常重试。
4. 将异常动作映射到 MITRE ATT&CK for ICS，但只有报文、日志、配置差异或设备状态才能确认路径；技术编号不能替代事件证据。
5. 对漏洞通告核对精确型号、固件、模块、启用功能和网络可达性；优先查厂商公告与 CISA ICS Advisory，再判断是否具备当前环境的触发条件。
6. 固件和工程文件优先离线分析：签名、文件系统、服务、默认配置、凭据、证书、更新链、组件版本、项目差异和逻辑变更。
7. 需要主动协议验证时，先定义允许的地址、功能码、速率、设备状态、停止条件和回滚方式。默认不写线圈/寄存器、不下载逻辑、不改设定值、不切模式、不刷固件。
8. 使用 `blue-vulnerability-patterns` 的 OT 分片扩展管理面、工程师站、历史库、网关和
   备份通道；历史报告不能降低被动优先和禁止写控制状态的安全门槛。
9. 事件调查转 `blue-incident-reconstruction`，Web/HMI/API 转 `blue-vuln-retest`，结论交 `blue-evidence-validation`。

## Evidence Model

- `network-observed`：报文或会话已观察，未必到达控制逻辑。
- `controller-accepted`：控制器确认接受请求。
- `logic-changed`：程序、组态或参数存在可验证差异。
- `process-affected`：遥测或物理过程发生对应变化。
- `safety-affected`：保护、联锁或安全功能受到影响。

不得从 `network-observed` 直接推断 `process-affected`。

## References

需要协议端口、首轮观察字段和权威资料层级时读取 [references/standards-and-protocols.md](references/standards-and-protocols.md)。

## Output

输出资产与过程上下文、正常基线、异常时间线、ATT&CK for ICS 映射、精确版本适用性、网络到控制/物理影响的证据等级、检测点、处置优先级和回滚条件。
