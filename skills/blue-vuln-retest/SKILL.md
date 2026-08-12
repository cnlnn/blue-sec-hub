---
name: blue-vuln-retest
description: 对厂商、扫描器、内部团队或历史记录提交的漏洞报告进行复测和整改验证。输入可以是 PDF、Word、Excel、Markdown、截图、请求包、URL 或简要复现步骤；用于确认漏洞是否仍存在、是否修复、影响是否准确以及修复是否引入回归。
---

# Vulnerability Retest

## Workflow

1. 保留原报告，先用 `blue-report-ingestion` 复用版本化提取结果，再核对目标、入口、前置条件、身份、请求形状、预期现象、影响和修复声明。
2. 用 `blue-report-intelligence` 查询相同系统、组件、对象、根因、入口和修复范围；区分报告声称的历史事实与本次实际观察。
3. 先恢复正常业务请求，再改变单一变量复测；不要从扫描器结论直接跳到漏洞结论。
4. 使用 `blue-security-knowledge` 和 `blue-vulnerability-patterns` 查找对应专项方法、相邻
   生命周期及修复边界。涉及对象所有权时先执行匿名、低权限、主体绑定和自有对象模式；
   只有真实跨主体所有权需要第二身份。涉及源码时使用 `bug-hunter`。
   需要验证过滤、编码或规范化修复绕过时按漏洞族检索 `blue-sec-payload-catalog`，比较
   原始变体与当前修复边界；目录中的危险 payload 只能作为候选，仍须遵守当前目标的
   `safe-auto`、`needs-agent` 和 `blocked` 决策。
5. 保存本次请求、响应、时间、账号角色、环境版本、代码位置和清理结果。
6. 使用 `blue-evidence-validation` 复核可达性、可重复性、影响和替代解释。
7. 将复测结论作为新的 `current` 记录写回报告情报库，不覆盖攻击队或厂商的历史记录，并重新计算组合链和绕过候选。

报告中的对象 ID、ticket、文件 key、业务状态和请求包只作为历史种子。当前复测必须先从
本轮列表、详情、菜单、创建响应或协议流量重新找到生产者，并证明它进入真实消费者；
缺失时进入 `waiting-prerequisite` 继续发现。不得用随机不存在值或历史他人对象得出
“无法越权”或“已修复”。

## Verdicts

- `confirmed-present`: 当前可稳定复现。
- `fixed`: 原路径不可复现且修复机制得到证据支持。
- `partially-fixed`: 原路径受阻但等价路径或影响仍存在。
- `not-reproduced`: 当前未复现，不能等同于已修复。
- `environment-mismatch`: 版本、配置、账号或数据条件不同。
- `insufficient-evidence`: 原报告或当前证据不足。

## Output

先给结论和新证据，再列复现差异、影响、清理状态和整改建议。不要用历史截图替代本次验证。
