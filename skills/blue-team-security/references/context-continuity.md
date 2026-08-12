# Context Continuity

用于可能跨越多轮、子 Agent、平台切换或自动上下文压缩的安全任务。用户不维护摘要；
宿主模型和执行器负责把关键状态外置到任务目录。

非 Web 长任务首次进入任务目录时自动运行
`blue-sec-context init --workspace <dir> --task-kind <kind> --target <target>`；Web 任务由
`blue-sec-agent` 自动初始化，不重复创建上下文。

## Source Of Truth

聊天摘要只用于导航，不能作为漏洞、覆盖或排除结论的证据。恢复时按以下顺序读取：

1. 目标、范围、安全边界、身份和业务状态；
2. `context-capsule.json` 的关键线索、当前动作、失败门槛和恢复顺序；
3. 胶囊列出的 canonical source 及 SHA-256；
4. 当前 evidence、inventory、plan、event ledger 和清理状态；
5. 最后才参考自然语言报告或聊天摘要。

canonical source 哈希变化时，旧胶囊标为 stale 并立即重建。自然语言 `results.md` 不能
反向覆盖机器状态。

## Preservation Priority

压缩时按以下优先级保留，不能只保留“结论”：

1. `critical`：目标与范围、安全禁止项、凭据可用性、已确认发现、实际影响、清理失败、
   P0/P1 未决动作和会改变攻击路径的证据；
2. `high`：身份/角色/租户、对象与父级、业务状态、请求形状、正负对照、候选漏洞、
   相邻接口、WAF/验证码/限速状态和关键排除理由；
3. `normal`：P2/P3 队列、普通攻击面、工具状态和后续检查；
4. `low`：可从 canonical source 重建的叙述、重复输出和展示细节。

永不静默删除失败采集、未访问路由、未验证 API、未映射控件、未执行测试、矛盾证据、
负向结果适用边界和“为什么不是漏洞”。列表超出胶囊预算时保留数量、优先项和原始文件
引用，完整账本仍在任务目录。

## Event Rules

需要补充模型才能表达的线索时，生成临时 JSON 并调用
`blue-sec-context record --workspace <dir> --event <file>`。事件类型限定为：

- `fact`、`hypothesis`、`decision`、`next-action`、`blocker`；
- `scope`、`finding`、`rejected`、`evidence-anchor`；
- 宿主补漏只能写 `provisional`、`session-boundary`，恢复后必须核验，不能直接当作事实。

事件包含稳定 `id`、`priority`、`status`、简短 `summary` 和 canonical `refs`。后续证据
推翻旧线索时用 `replaces`，不修改原事件。不得写入 Cookie、Token、Header、请求或响应
正文、密码、个人数据及原始 payload；这些只留在受控证据层。

## Compression And Resume Gate

- 目标、范围、证据、结论、假设、排除项、决策、阻塞或下一动作形成时先写事件账本，
  然后继续工作；不能等待模型感觉接近 Token 上限。
- 关键状态提交、任务结束和宿主压缩前自动运行
  `blue-sec-context checkpoint --trigger <event>`；宿主有原生压缩钩子时只用于补漏。
- 压缩或平台切换后运行 `blue-sec-context restore`。它会审计 source hash、自动重建陈旧
  胶囊，并标出必须核验的 `provisional` 线索。
- 恢复后的第一个动作必须来自仍有效的机器队列；不得重复已结算动作，也不得跳过胶囊
  中的 P2/P3 或安全可执行项。
- 胶囊本身不满足 coverage、finding 或 evidence 门槛，只防止线索和任务状态在压缩时
  丢失。
- 任务状态只进入任务 workspace；平台全局 memory 只能保存经学习审查批准的长期偏好、
  操作规则和通用模式，不保存目标、账号、对象 ID、证据正文或临时 TODO。
