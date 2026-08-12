---
name: blue-local-knowledge
description: 检索用户本机已经索引的历史漏洞报告、复测记录、攻击事件、日志摘录和研究笔记。遇到相似漏洞、相同产品、接口、攻击手法、IOC、整改方案或用户要求参考历史经验时使用；本地材料仅作为历史证据和候选方法，必须与当前目标重新核对。
---

# Local Security Knowledge

内部资料索引位于 `${BLUE_SEC_DATA:-~/.local/share/blue-sec-hub}/internal/`，不进入 Git 仓库，也不上传到公共知识源。

## Search

报告索引和非结构化内部材料是两个独立来源。已知当前系统、域名或 IP 时先查脱敏报告
摘要：

```bash
blue-sec-report-ingest search --system '<hostname-or-ip>' --json
blue-sec-report-ingest search --query '<product-or-weakness>' --json
```

再用具体产品、接口、CVE、漏洞类型、IOC 或协议检索非结构化材料：

```bash
blue-sec-search --source internal '<keyword>'
```

任一来源没有结果都继续当前任务，不要求用户维护分类、标签或授权信封。用户提供新的
报告目录时由 Agent 持久配置并建立报告索引；其他事件材料按需进入内部全文索引：

```bash
blue-sec-config add-report-root <directory>
blue-sec-report-ingest scan --configured
```

聊天缓存或持续增长的混合资料目录使用 `--mode security-reports`，由
`blue-sec-knowledge-distill` 对现代/旧版 Office、报告型 HTML、扫描件和安全归档做
增量处置。用户明确说“本次对话临时知识库”时不得写入长期配置；使用
`blue-sec-knowledge-session open`，完成检索和通用提炼后调用 `close` 自动删除会话派生
数据。长期知识源有变化时按需增量刷新，不启动后台守护进程。

## Use

1. 引用命中的原始来源路径和 SHA-256。
2. 把历史结论标记为 `historical`，当前重新验证后才能标记 `confirmed`。
3. 优先复用经过验证的请求形状、解析脚本、证据格式和排除路径。
4. 不把另一个版本、环境、账号或资产的结论直接迁移到当前目标。
5. 需要跨报告生成系统漏洞画像、同源漏洞、修复绕过或组合链时使用 `blue-report-intelligence`，不要只靠全文关键词拼接。
6. 需要把多份历史漏洞转换为目标无关的测试方法时使用
   `blue-vulnerability-patterns`；扫描器单一结果和站点特征只能留在候选层。
