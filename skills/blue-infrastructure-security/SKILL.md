---
name: blue-infrastructure-security
description: 对主机操作系统、中间件、数据库、网络设备、虚拟化、容器基础设施和管理面进行授权巡查、漏洞复测、基线核验与修复验证。输入可以是资产清单、配置、版本、扫描报告、命令输出或管理接口；用于区分真实可利用组件漏洞、补丁回移、配置风险、默认认证和暴露面，不把扫描器或 Banner 单独当作漏洞。
---

# Infrastructure Security

## Workflow

1. 建立资产、环境、网络区、管理面、组件版本、补丁来源和配置基线；生产、测试、集群
   节点和容器镜像分开记录。
2. 报告和扫描结果先用 `blue-report-ingestion` 读取，再用
   `blue-vulnerability-patterns` 的 `references/infrastructure.json` 生成验证矩阵。
3. 对 CVE 同时核对产品分支、发行版回移补丁、功能启用、配置前置条件、网络可达性和
   当前响应；Banner、CPE 或扫描器签名单独出现时保持 `candidate`。
4. 优先执行配置读取、包版本、补丁元数据、服务能力和良性协议握手。会修改账号、服务、
   路由、防火墙、集群状态或数据的动作必须明确可恢复并保存前态。
5. 弱口令验证不得做密码喷洒或触发锁定。使用提供的测试账号、配置证据、匿名安全读取或
   一次明确记录的默认凭据检查。
6. 对管理面、原生协议、Web 控制台、API、备份接口、旧节点、镜像和灾备环境做相邻扩展，
   但不跨越未授权网络区或第三方资产。
7. 使用 `blue-evidence-validation` 复核真实影响；修复后同时验证原入口、等价接口、旧版本
   节点和配置回退，不能仅依据版本字符串宣布修复。
8. 容器和集群环境额外建立 workload identity、ServiceAccount、RoleBinding、namespace、
   token audience/expiry、代理代带凭据和 controller reconciliation 关系。只读核对最小权限、
   目标 allowlist、跨 namespace 能力和“状态写入 -> 控制器调谐 -> 高权限动作”链；没有第二个
   独立系统证据的历史模式只作为 `local-hypothesis`。
9. 监控、日志、告警和流式控制面分别结算读取、写入、管理和生命周期权限。服务可达、
   空握手或 routing key 本身不是漏洞；状态写入、凭据转发或会话抢占必须有当前影响证据。

## Safety

- 默认禁止破坏性公共 PoC、拒绝服务、密码喷洒、固件写入、集群重配置和生产数据修改。
- OT/ICS、PLC、HMI、SIS 和工业协议转交 `blue-ot-security`，沿用其更严格的被动优先
  约束。
- 需要公开研究环境复现时使用 `blue-reproduction-lab`，不要在生产资产上验证代码执行。

## Output

分别输出 `confirmed`、`historical`、`candidate`、`not-applicable`、`fixed` 和
`blocked`，并给出资产版本、补丁证据、配置证据、可达性、验证时间、替代解释和清理
状态。
