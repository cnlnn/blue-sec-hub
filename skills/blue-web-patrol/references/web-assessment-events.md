# Web Assessment Events

`assessment-events.jsonl` 是追加式任务日志。每行一个 JSON object；控制程序重放事件
生成 coverage、test plan、evidence index 和报告。不要直接编辑派生产物来改变结论。

## Common Fields

- `type`: 事件类型。
- `recorded_at`: 可省略，控制程序写入 UTC 时间。
- `evidence_refs`: 指向 `evidence` 事件已登记的路径或 ID。

## Evidence

```json
{"type":"evidence","path":"evidence/request-001.json","kind":"request-response","sha256":"..."}
```

证据原件留在任务目录。索引可以记录相对路径、哈希、身份、业务状态、时间和脱敏摘要，
不能复制 Cookie、Token、口令或真实业务数据。

## Phase And History

```json
{"type":"phase","phase_id":"related-passive-discovery","status":"completed","evidence_refs":["evidence/browser.json"]}
{"type":"history-lookup","status":"completed-no-match","target_keys":["portal.example.test"]}
```

阶段状态使用 `completed`、`blocked`、`not-applicable` 或未完成状态。`blocked` 和
`not-applicable` 必须带原因或 gap；历史结论只能作为本次验证种子。
`blocked` 是调度终态，不是覆盖满足状态；只有 `tested` 和有证据的
`not-applicable` 可以满足完整覆盖。

## Surface And Dimensions

```json
{"type":"surface-discovered","surface":{"kind":"api","method":"GET","url":"/api/v1/items","validation_state":"runtime-observed","runtime_observed":true}}
{"type":"identity","id":"role-reviewer","status":"observed","evidence_refs":["evidence/menu-reviewer.json"]}
{"type":"business-state","id":"pending-approval","status":"observed","evidence_refs":["evidence/pending.json"]}
```

可选 surface 字段包括 `fields`、`profiles`、`safety` 和 `risk_factors`。`safety` 只能
是 `passive`、`read-only`、`reversible` 或 `blocked`；只有自有测试对象且能清理时
才标记 `reversible`。

授权能力按模式单独登记：

```json
{"type":"authorization-capability","id":"low-privilege-function","status":"available","evidence_refs":["evidence/session-shape.json"]}
{"type":"authorization-capability","id":"cross-principal-ownership","status":"unavailable","reason":"second authorized principal unavailable"}
```

`id` 使用 `anonymous-boundary`、`low-privilege-function`、
`implicit-subject-binding`、`self-owned-object`、
`cross-principal-ownership`、`tenant-parent-binding`、
`protected-property`、`workflow-precondition` 或 `state-transition`。

捕获的请求只保存形状，不保存 Header、Cookie、Token 或正文值：

```json
{"type":"request-shape","surface_ref":"surface-...","method":"POST","path":"/api/items/query","source":"runtime","semantics":"read","body_fields":["ownerId","page"],"safety":"read-only","credential_values_persisted":false}
```

`source` 为 `runtime`、`har`、`openapi`、`documented`、`historical`、
`manual` 或 `surface-validation`。写入形状只有在自有对象且
`cleanup_evidence_refs` 非空时才会生成可执行 case。

## Route And Control Results

```json
{"type":"route-result","route_id":"route-...","test_case_id":"route-case-...","status":"tested","stages":{"current-validated":"completed","navigated":"completed","rendered":"completed","controls-extracted":"completed","runtime-api-linked":"completed"},"evidence_refs":["evidence/route-render.json"]}
{"type":"control-result","test_case_id":"control-case-...","status":"blocked","reason":"write action lacks a cleanup-safe self-owned object"}
{"type":"surface-link","from":"route-...","to":"surface-...","relation":"runtime-api","evidence_refs":["evidence/browser.json"]}
```

路由 case 使用 `route-navigation`，控件 case 使用 `ui-interaction`，HTTP 测试使用
`api-test`。`route-result` 的 `tested` 必须有本次渲染证据；`page.goto` 成功、历史
路由或 SPA shell 不能完成 `rendered`。动态参数只记录来源和是否保存值，不能把真实
对象值写入事件日志。

## Runner Execution

```json
{"type":"credential-lease-state","status":"available","source":"burp-current-request","header_names":["Authorization"],"fingerprint":"..."}
{"type":"runner-checkpoint","status":"running","phase":"risk-execution","iteration":12}
{"type":"variant-result","test_case_id":"test-case-...","variant_id":"anonymous-variant","status":"tested","evidence_refs":["evidence/runner/result.json"],"oracle":{"equivalent_structure":false}}
{"type":"execution-audit","status":"blocked","counts":{"auto_unresolved":0,"needs_agent":3},"gaps":["agent-case:..."]}
```

凭据 lease 事件不得包含值；JWT 摘要只允许 claim 名、敏感 claim 名、数量和
`values_persisted: false`。浏览器原始请求语料只允许存在于 Runner 的 `0600` 瞬时
文件和内存中，读入后立即删除。自动 case 的每个 `variant_id` 必须分别结算；case 的汇总
`test-result` 不能代替变体证据。独立审计只有在自动队列、变体、路由和 agent-review
缺口全部处理后才可标记 `passed`。

## Test Result

```json
{"type":"test-result","test_cell_id":"cell-...","test_case_id":"test-case-...","status":"tested","evidence_refs":["evidence/request-001.json"],"authorization_evidence":["anonymous-authenticated-differential"],"negative_result":true}
{"type":"test-result","test_cell_id":"cell-...","status":"blocked","reason":"test account unavailable"}
{"type":"test-result","test_cell_id":"cell-...","status":"not-applicable","reason":"no XML parser on mapped workflow","evidence_refs":["evidence/content-types.json"]}
```

`tested` 和 `not-applicable` 必须有证据。`blocked` 和 `not-applicable` 必须有原因。
`reversible` 测试还要包含
`"cleanup":{"status":"completed","evidence_refs":[...]}`。负向结果自动绑定当时的
surface fingerprint；攻击面变化后重新排队。

授权 test cell 有可执行 case 时，`tested` 必须关联 `test_case_id` 并提供对应
`authorization_evidence`。`nonexistent-object-only`、`request-handler-only`、
`validation-error-only` 和 `ui-hidden-only` 不能结算授权测试。

## Candidate And Finding

```json
{"type":"candidate","id":"candidate-01","title":"compound policy signal","surface_refs":["surface-..."],"validation_dependencies":[{"id":"concrete-endpoint","kind":"endpoint-reachability","status":"satisfied","evidence_refs":["evidence/current-endpoint.json"]},{"id":"protected-impact","kind":"impact","status":"pending","reason":"protected response has not been identified","resolution_action":"discover-protected-consumer"}]}
{"type":"candidate-dependency","id":"candidate-01","dependency_id":"protected-impact","status":"exhausted-with-evidence","reason":"all current protected routes and APIs were checked without a matching consumer","evidence_refs":["evidence/protected-surface-ledger.json"]}
{"type":"finding","id":"finding-01","title":"confirmed issue","validation_state":"confirmed","evidence_refs":["evidence/control.json"],"surface_refs":["surface-..."]}
{"type":"candidate-disposition","id":"candidate-01","disposition":"rejected","reason":"random-path control produced the same response"}
```

外部执行器结果始终先记录为 candidate。只有 `validation_state=confirmed` 且存在独立
证据时才进入 finding。复合候选的每个前提使用 `pending`、`satisfied`、
`exhausted-with-evidence` 或 `blocked`；`satisfied` 和 `exhausted-with-evidence` 必须有
本轮证据。`pending`/`blocked` 会生成 Agent 动作并阻止完成，
`exhausted-with-evidence` 只能支持拒绝候选，不能支持确认。`deferred-with-reason` 不属于
已处置状态。

## Universal Prerequisite

```json
{"type":"prerequisite-result","prerequisite_id":"prerequisite-...","owner_kind":"test-case","owner_id":"test-case-...","status":"searching","strategy_id":"runtime-traffic","strategy_status":"completed","reason":"current runtime traffic did not expose an owned object producer","evidence_refs":["evidence/runtime-producer-search.json"]}
```

状态只能是 `pending`、`searching`、`satisfied`、`exhausted-with-evidence` 或
`blocked-external`。`satisfied`、`exhausted-with-evidence` 和 `blocked-external` 必须有
本轮证据；穷尽还要求全部适用策略有处置且连续两轮无新增。兼容的
`candidate-dependency` 会迁移为相同 prerequisite 节点。缺少 ID、生产者、请求形状、
消费入口、业务状态、协议上下文或清理动作时，test case 使用
`waiting-prerequisite`，不能直接写 `blocked` 或 `not-applicable`。

## Missed Finding

```json
{"type":"missed-finding","title":"late finding","cause":"discovery","surface_refs":["surface-..."],"evidence_refs":["evidence/late.json"]}
```

`cause` 只能是 `discovery`、`mapping`、`applicability`、`priority`、`execution`、
`validation` 或 `evidence`。通用改进交 `blue-skill-learning`；目标细节只留在任务
证据。

## Runtime Conditions

```json
{"type":"credential-state","status":"expired","reason":"session redirected to login"}
{"type":"runtime-condition","kind":"waf","status":"blocked","reason":"challenge page replaced application response","retry_after":"2026-07-26T02:00:00Z"}
```

网络失败、验证码、WAF、限速、工具缺失和凭据失效不能被记作安全结论。保留失败证据、
解除条件和重试时间后继续其他可执行单元。

## Dynamic Priority Events

AI 只能提交带 `target_kind`、`target_id`、受支持 `factor`、`reason` 和非空
`evidence_refs` 的 `priority-signal`，不得提交最终分数或正式严重性。负向因素还必须声明
`evidence_state=confirmed|exhausted-with-evidence`；超时、随机对象空响应、扫描器无结果、
网络失败和账号缺失不能降级。运行时确定性生成 `priority-change`；实际抢占和公平调度可记录
`queue-preemption`、`starvation-promotion`。这些事件只改变执行顺序，不改变范围、结论状态、
CVSS 或完成门槛。
