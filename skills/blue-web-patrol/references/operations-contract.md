# Web Patrol Operations Contract

本文件保存从 SKILL.md 下沉的完整操作合同，按需读取；内容与 SKILL.md 原文逐字一致。
SKILL.md 中的对应条目是摘要与指针。

## Single-Account Authorization Model

单账号不是整个授权域的 blocker。分别结算：

- `anonymous-boundary`：登录与匿名精确对照；
- `low-privilege-function`：低权限对管理、审批、配置和隐藏功能的强制访问；
- `implicit-subject-binding`：主体字段省略、重复或冲突时的服务端绑定；
- `self-owned-object` 和 `protected-property`：本轮自建可清理对象及其受保护字段；
- `workflow-precondition`、`state-transition`、`tenant-parent-binding`；
- `cross-principal-ownership`：只在具备第二授权主体时执行。

只有最后一项必须依赖第二主体。随机不存在 ID、空正文、缺字段或参数错误只证明处理器可达，
不能结算对象授权。UI 隐藏而接口可达先记 candidate；BFLA 还需策略、源码、权限元数据或可重复
影响。没有第二主体时水平越权保持 `blocked` 或 hypothesis，不能被匿名测试替代。

## Universal Prerequisite Closure

所有 case、candidate、route、control 和攻击链都必须闭合前提。缺少本轮对象 ID、请求形状、
自有对象、业务状态、输入位置、消费 sink、协议上下文或清理动作时，进入
`waiting-prerequisite`，并在 `prerequisite-graph.json` 生成
`resolve-prerequisite`，不得降成普通 blocker。candidate 的 `validation_dependencies`
迁移为同类节点。

对象只能来自本轮当前账号可见、自有、公开或本轮自建对象。禁止以历史他人 ID、未知所有权
ID、顺序枚举或随机不存在 ID 满足授权基线。状态含 `pending`、`searching`、`satisfied`、
`exhausted-with-evidence` 和 `blocked-external`；只有 `satisfied` 可执行原 case。
`exhausted-with-evidence` 只能排除候选或形成明确 blocker，不能确认漏洞或伪装成
`not-applicable`。例如 CORS 必须证明具体受保护响应可被目标 Origin 在携带受害者凭据时读取；
公开响应、攻击者自带 Bearer Token 或不兼容的 credential mode 是反证。

## Constraint And Differential Analysis

为每个工作流主动判断约束删除或放宽、身份/对象/状态替换、生命周期差异、解析差异、
生产者到消费者差异和跨功能组合。认证接口比较账号存在性、限速、业务码、字段、长度和
时序；challenge/ticket/pre-auth session 检查身份、用途、渠道、会话、时效和一次性绑定；
Token/JWT 检查 claim 最小化；客户端配置检查内部地址、权限和开关；edge/backend 比较
规范化；文件、URL、路径和内容必须追踪到审批、发布、执行、下载及删除消费者。

## Surface Change Invalidation

攻击面变化后，旧负向结论按 surface fingerprint、身份、状态、请求形状和时间失效并重新排队。

## Evidence Provenance And Traffic History

每个前提必须标注来源：`attacker-public`、`attacker-authenticated`、
`attacker-derived`、`tester-provided`、`historical-report`、`internal-log` 或
`source-code`。黑盒攻击链只有前三类可以闭合攻击者前提；日志附件、历史对象 ID、测试人员提供值
和源码常量只能作为搜索种子，除非攻击者模型明确包含相同访问能力。发现内部 consumer 后必须继续寻找
攻击者可达 producer，形成实时 `producer -> controlled object -> consumer -> impact` 链。

Burp、HAR 和代理历史必须记录检索时间范围、数据源、分页覆盖、损坏记录和解析失败。解析器遇到损坏
控制字符或单条坏记录时应隔离该记录并继续扫描；登录态以最新成功认证响应及其后的有效受保护请求综合
判断，不能因一次解析失败或较早失败响应断言会话不存在。随机、失效或未知所有权对象的空响应不能证明
漏洞已修复；必须使用本轮实时生产的有效对象和匹配对照重测。

## Defaults And Protocol Disposition

默认匿名、同源、`2 req/s`，交叉使用静态资源、浏览器运行时、HAR、路由、控件和协议
文档。核心不得自动下载或依赖第三方扫描器。GraphQL 只用本轮观察到的请求形状和
`__typename`；OAuth/OIDC 只读取已发现 metadata/JWKS；WebSocket/SSE、SOAP/XML、
gRPC 分别记录处置。无组织自有 OAST 时 SSRF/XXE 回连验证为 `blocked`。
