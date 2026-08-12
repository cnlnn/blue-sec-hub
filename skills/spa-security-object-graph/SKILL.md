---
name: spa-security-object-graph
description: 从任意 JavaScript-heavy SPA 的页面、路由、前端资源、API 封装和浏览器流量重建业务对象、技术资源、身份角色、控制条件与生命周期关系；也用于分析 Electron ASAR 解包后的 main、preload、renderer、webPreferences 和 IPC 特权桥。用于站点巡查、桌面 Web 壳审计、漏洞复测、攻击面扩展和跨功能授权分析，发现 IDOR/BOLA/越权、隐藏接口、客户端可控对象引用、状态机绕过及敏感能力组合链；不依赖特定站点、产品或业务领域，也可处理本地已采集资源。静态高影响节点缺少输入、特权桥或影响证据时必须保持 candidate 并继续验证，不得直接判 not-a-finding。
---

# SPA Security Object Graph

把接口清单转为带证据强度的对象关系和控制边界。所有结论必须关联源码位置、页面动作或本次捕获的流量；脚本只生成候选，不生成漏洞定论。
建图时可读取 `blue-vulnerability-patterns` 的授权、主体绑定、父级关系和状态机通用模式，
但不得把历史业务名称或接口词直接加入语义词表。

Electron/ASAR 输入先保留原包哈希并解包到分析副本，再分别建立
`attacker source -> renderer input -> script sink -> preload/IPC bridge -> main-process consumer -> OS impact`
关系。`webPreferences`、Node 能力或 IPC handler 只确认静态节点；没有可控输入、运行时可达性
和受控 OS 结果时保留风险候选并继续寻找前置链，不能写成已确认 RCE。
固定输出门槛：只要上述静态高影响节点存在且任一前提尚未验证，必须返回
`validation_state=candidate`、`conclusion_state=candidate`、`formal_severity=null`、
`confirmed_impact=null`、`continue_investigation=true`。只有证据证明设计上安全或已通过反证
排除该路径时才允许 `not-a-finding`；“尚未发现 XSS/可控输入”本身不是排除证据。

## Start

只有 URL 或域名时直接采集同源 SPA：

```bash
blue-sec-spa-graph https://example.test --out <output-dir>
```

需要 lazy-loaded chunk 时增加 `--browser`。浏览器默认穷尽当前同源路由队列，不设
固定页面上限。路由名称不是 HTTP 副作用：包含
`create/update/delete/download/export/reset` 的页面仍执行只读导航；浏览器网络守卫
允许文档、静态资源、安全方法和已识别的查询型 `POST`，其他页面触发请求进入
`blockedRequests`，不能静默放行。动态路由参数只能来自本次运行时、自有对象或文档，
否则保留为 `routesBlockedParameters`。

站点巡查默认同时使用：

```bash
blue-sec-spa-graph https://example.test --browser --verify-safe-reads \
  --out <output-dir>
```

只有明确 time-boxed 时才设置 `--browser-pages <count>`；默认 `0` 表示持续到路由、
lazy chunk、控件和运行时 API 队列收敛。标签页、分页、筛选、预览和只读弹窗会自动
操作；危险控件保留为可见测试债务，直到存在自有对象和清理证据。

以 `analysis/surface-inventory.json` 作为功能、路由和 API 的统一机器清单。
`graph.json` 中的静态字符串只是候选，不得直接当成已确认接口数量。

认证信息放在权限 `0600` 的临时 Header 文件中，通过 `--header-file` 引用，采集完成后
删除；SPA 登录态必要时用 `--browser-storage-state` 恢复，`header-only-auth-incomplete`
不得当成登录态攻击面；运行时 XHR/fetch JSON 只落盘字段结构与哈希，原值仅内存关联。
机制细节见 [browser-runtime.md](references/browser-runtime.md)。

已有本地资源时运行：

```bash
python scripts/build_object_graph.py <asset-dir> --out <output-dir>
```

先读 `report.md`，再回到高分端点对应的原文件。多步 UI 状态依赖无法从静态资源确认时，补充 HAR 或浏览器采集。

## Surface Closure Contract

仅存在于服务端、未下发给当前身份或受业务状态控制的功能无法从匿名前端凭空推出，
因此本 Skill 保证“不静默遗漏”，不声称绝对零遗漏。功能、路由、资源、控件、API、
身份和状态必须分别结算；队列、失败、拒绝和未知维度全部保留。`validApis` 仅包含运行时
请求或经安全只读验证的接口，`401/403`、假 `200` 和静态字符串不能升级为成功或漏洞。
完整九项规则见 [surface-closure.md](references/surface-closure.md)。

## Taxonomy

机器分类统一使用稳定英文 ID，中文和英文只作为别名：

- `actor`
- `business_object`
- `resource`
- `write_action`
- `read_action`
- `lifecycle_action`
- `gate`
- `public_boundary`
- `sensitive_capability`

基础词表位于 [references/semantic-lexicon.json](references/semantic-lexicon.json)。
本地候选补充、别名语义和合入门槛见
[lexicon-governance.md](references/lexicon-governance.md)。

## Workflow

### 1. 保留功能上下文

按 lazy chunk、路由、组件、调用函数和相邻 UI 文本聚类 API。保留文件名、行号、字节偏移、HTTP 方法、请求字段和相邻端点，不能压平成无上下文的路径列表。

### 2. 建立通用对象图

从当前站点动态识别：

- 身份与角色；
- 业务对象与技术资源；
- 对象标识和版本、状态、容量、金额等客户端字段；
- 每个 opaque 标识的本次生产者、语义别名、消费者、身份上下文和可获得性；
- 创建、读取、变更和生命周期操作；
- 认证、授权、所有权、租户、成员、审批、资格、额度、状态和时间条件；
- 管理、凭据、个人信息、资金、文件传输、执行和消息等敏感能力。

仅在 `observed-value-reuse`、`shared-object-field`、`same-api-family`、
`same-feature-chunk` 等证据支持时建立边。同文件邻近和关键词重合只是弱线索。

### 3. 结构证据优先

端点评分优先使用 HTTP 写方法、请求字段、共享标识、值复用、生命周期配对、跨命名空间
关系和身份边界；领域词只加分，不是硬门槛。对每个状态变更端点回答：接收哪些标识/
状态/限制字段、哪个列表或详情接口提供值、预期控制条件、服务端推导还是客户端选择、
哪个接口能证明结果。敏感消费者必须可回溯到当前身份可达的标识生产者；无生产者时
`waiting-prerequisite` 并继续搜索，不能提前结算。完整规则见
[heuristics.md](references/heuristics.md)。

### 4. 重建真实请求

依次优先使用浏览器流量、source map 调用点、组件提交函数、API wrapper，最后才做受控
推断；记录每个 Header、路径和 Body 字段的来源，复用前端实际基础路径和 Header 后再
判断 `401`、`403` 或参数错误。见 [heuristics.md](references/heuristics.md)。

### 5. 最小扰动验证

真实跨主体对象所有权用两个已授权账号；匿名边界、低权限功能、隐式主体绑定、自有
对象、受保护属性和业务状态不依赖第二账号。先只读和故意不完整的写请求；状态变更只用
最小规格、唯一标记、单次请求，立即验证和清理。严格区分 endpoint reachability /
parameter validation / successful state change / unauthorized impact / downstream
control——HTTP `200` 不能单独证明后三项。见 [heuristics.md](references/heuristics.md)。

### 6. 输出攻击路径候选

`actor -> prerequisite object -> client-controlled fields -> state-change API ->
resulting object/capability -> verification API/UI -> impact`；列出预期规则、观测规则、
字段来源、证据类型、请求响应、清理状态和置信度。优先级与误报控制见
[heuristics.md](references/heuristics.md)。

## Semantic Extension Gate

本 Skill 的自更新和上游补充遵循 `blue-skill-learning` 的整合包统一普适性门槛。
SPA 语义层另需满足：机器分类保持稳定；领域名词只能增加召回和排序；至少通过
两个无关业务领域，以及一个不命中领域词、仅依靠共享对象字段建图的 Fixture。
未达到这些专项条件的词表补充只留在本地候选层。

## Completion Gate

不能停在路由清单。必须使用 `surface-inventory.json` 的 completion blockers：
高风险状态变更端点已有前置条件图，未解析字段已列出，合理控制门槛已验证或明确标记
未测试，且当前确认行为与假设分开。任何 blocker 存在时只能报告阶段性覆盖，继续补采
或明确说明需要哪种身份、状态或后端证据才能解除。`corsCandidates` 必须区分浏览器
可读的单一 Origin 反射、多重响应头造成的浏览器拒绝，以及尚缺登录态影响验证的候选。
