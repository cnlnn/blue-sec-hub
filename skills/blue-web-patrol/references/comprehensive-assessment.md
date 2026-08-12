# Comprehensive Web Assessment

本参考用于开放式 Web、SPA 和 API 测试。它是覆盖域，不是固定 payload 列表；先从
实际功能和数据流中选择相关验证。

## Surface Model

至少覆盖以下入口类型：

- 公共页面、登录后页面、管理页面、隐藏路由、lazy chunk 和旧版本入口；
- REST、GraphQL、WebSocket、SSE、批量接口、异步任务和移动端/合作方 API；
- 查询、详情、创建、修改、删除、审批、发布、分派、重置、导入、导出和下载；
- 富文本、搜索、筛选、模板、URL、回调、文件名、压缩包、Office 文档和图片处理；
- 身份、角色、租户、团队、业务对象、父子对象、状态机和外部系统边界。

对大型系统记录总量和抽样策略。只加载主 bundle 或只浏览当前角色菜单，不能视为
完整攻击面。

## Discovery Passes

发现过程保存在 `coverage.json`，各轮可以交错执行，但不能因一轮扫描或一个高危发现
而跳过其余轮次：

1. **历史差异轮**：用精确资产、产品和组件键检索已索引报告、当前任务目录和内部
   知识。把历史入口、根因、前置条件和修复声明转换为本次验证种子，同时保留
   `historical` 状态。
2. **运行时基线轮**：按匿名和每个可用身份走主要功能，合并浏览器、Burp、静态资源
   和接口定义，记录角色看不见但资源中存在的入口。
3. **主动假设轮**：对每个高价值工作流判断并验证以下通用变化：
   - 删除、清空或放宽客户端筛选、租户、状态、分页和范围约束；
   - 替换身份、对象、父对象、角色、租户和业务状态；
   - 比较 list/detail/create/update/approve/export/download 及单条/批量/旧版本；
   - 改变方法、参数位置、Content-Type、编码、文件扩展名与实际内容；
   - 沿输入生产者到页面、预览、发布、邮件、导出、转换器和后台任务等消费者追踪；
   - 将信息泄露、标识枚举、注册/邀请、文件能力和授权缺陷组合成可达路径。
4. **相邻扩展轮**：命中后检查同控制器、同对象生命周期、等价渠道、相邻角色和修复
   边界；未命中时记录已验证的实际 surface，而不是只写漏洞类型名称。

不设固定 payload 或请求数量来冒充深度。每个适用变化必须有运行时证据、明确阻塞项或
基于攻击面清单的 `not-applicable` 依据。

## Deterministic Planning

每个 surface 使用归一化 origin、方法、路径模板和协议生成稳定 ID。数字、UUID、
长哈希、Token、对象值和 query value 不参与 ID；同一入口在换账号或换对象后仍能与
旧证据关联。聚类后的 work unit 必须保留完整 `surface_refs` 和抽样记录。

风险总分为 0–20，组成项均写入 `test-plan.json`：

- 业务影响 0–4；未知时取 2，不能取 0；
- 外部可达性 0–3；
- 敏感数据或权限转换 0–4；
- 历史或运行时信号 0–3；
- 与其他入口组合的价值 0–3；
- 未知项和覆盖债务 0–3。

16–20 为 P0、11–15 为 P1、6–10 为 P2、0–5 为 P3。安全等级独立记录为
`passive`、`read-only`、`reversible` 或 `blocked`；不能通过降低风险分数隐藏无法
安全执行的高风险动作。

标准基线使用固定版本的 WSTG 4.2 和 ASVS 5.0.0；OWASP API Security Top 10 2023
与 OWASP Top 10 2025 只作风险覆盖提示。每个标准引用记录版本、source ref 和
source commit。同步到上游的新内容先作为候选，经通用性和回归验证后再改变正式测试族。

## Technology Profiles

根据运行时和文档证据自动启用 SPA、REST/OpenAPI、GraphQL、WebSocket/SSE、
SOAP/XML、OAuth/OIDC、文件处理、移动端后端和外部 API 集成 Profile。Profile 只增加
适用测试族和排序，不能删除原始 surface，也不能单凭技术关键词生成漏洞结论。

下载的 APK、IPA 或桌面客户端转交对应专项 Skill 提取真实 API、Header、证书策略和
协议，再把后端 surface 返回本矩阵。第三方集成只被动记录，除非它有独立范围依据。

## Test Domains

### Identity And Session

登录、注册、找回、MFA、SSO/OAuth、Cookie、JWT、刷新/注销、会话固定、并发会话、
CSRF、CORS 和敏感操作重新认证。登录、找回、短信、验证码和邀请需要比较响应差异与
限速状态；Token claim 还需按业务必要性检查个人、组织和内部标识是否最小化。

### Authorization

对象级、功能级、属性级、租户级、父子对象、批量对象、角色/权限赋予、隐藏管理接口、
文件令牌和不同业务状态下的授权。对比匿名、自身、同角色他人、跨角色和跨租户。

### Injection

根据真实解析器和 sink 检查 SQL/NoSQL、命令、模板、表达式、LDAP/XPath、日志/头部、
路径和解析差异。自动化无命中不能替代手工数据流验证。

### Browser And Content

反射/存储/DOM XSS、富文本和 Markdown、预览/发布差异、HTML Sanitizer、URL scheme、
DOM sink、postMessage、开放重定向、点击劫持和敏感数据在浏览器存储中的暴露。

### Server-Side Processing

SSRF、XXE、反序列化、模板/渲染、服务端请求、转换器、Webhook、回调、代理、解析器和
后台任务。优先使用无外带或受控回连的最小验证。

### Files And Data Export

上传类型/内容/扩展名差异、路径穿越、任意读取/下载、对象所有权、压缩包处理、图片/
文档解析、公开存储、导入覆盖、CSV/Excel 公式和导出权限。

### API And Protocol Variants

方法覆盖、Content-Type 混淆、重复参数、参数位置差异、批量/单条差异、版本旁路、
GraphQL introspection/field authorization、WebSocket 鉴权和缓存键差异。对受网关、
WAF 或代理保护的高价值动作，显式比较 edge/backend 对编码、分隔符、大小写、点段和
重复斜线的路径规范化，不能把普通参数变体当成已覆盖。

### Business Logic

状态跳转、步骤跳过、重放、竞态、幂等、配额、价格/数量、审批分离、邀请、分享、
归属转移、工作流分派和跨功能组合。共享文件 key、对象存储路径、URL、代码、内容或
对象标识的 producer、registrar、activator、consumer 和 cleanup 动作需要形成显式
链路，并保留各接口映射。使用自有对象或可逆操作，记录清理。

### Platform And Exposure

调试/文档/健康检查、默认配置、错误信息、缓存、Host/代理头、安全响应头、TLS、目录/
备份、云存储、第三方组件和已知版本风险。客户端 bootstrap、运行时 config/env/
settings 需要检查内部服务地址、环境标识、角色权限键、固定业务标识和危险功能开关。
版本线索需要当前证据确认。

## Depth Rules

- Scanner 结果只用于候选发现；至少用正常业务请求和运行时证据确认。
- `401/403/404/200` 本身不是授权结论；比较业务码、对象身份、响应字段和副作用。
- 不存在 ID 的拒绝不能证明真实对象安全。
- 一个入口安全不能外推到通用、批量、导出、下载或旧版本入口。
- 一个渲染点转义不能外推到编辑、预览、发布、邮件、导出或公共详情。
- 发现漏洞后检查同根因、同对象生命周期和可组合的前置/后置条件。
- Scanner 或外部 Agent 候选必须经过独立证据验证；其运行不能自动把 test cell 标成
  `tested`。
- 负向结论只对记录的 surface fingerprint、身份、业务状态、请求形状和时间有效；
  任一项变化都进入回归队列。
- WAF、验证码、凭据失效、限速、网络失败和工具缺失是带解除条件的 `blocked`，不是
  “没有漏洞”。
- 缺少可在当前应用内继续发现的 ID、请求形状、生产者、消费者、状态、输入位置或清理
  动作时使用 `waiting-prerequisite`，不是 `blocked`。只有证据化穷尽所有安全策略后才可
  转为明确 blocker；它仍阻止最终完成。
