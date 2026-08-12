# Blue Sec Hub

面向企业蓝队的安全 Skill 合集，让 AI Agent 更可靠地完成漏洞复测、Web/API 测试、
事件分析、流量分析、取证、恶意代码分析、移动端与工控安全等任务。

支持 Codex、Claude Code、Gemini、Grok Build、OpenCode、OpenClaw、Hermes、Trae
和 Trae CN。所有平台共用同一套 Skill、知识检索、证据标准和任务记忆。

## 主要特点

- 不把风险线索直接写成已确认漏洞；攻击前提和实际影响闭合后才给出正式结论。
- 任务状态写入本地账本，上下文压缩或切换 Agent 后可以继续恢复。
- 可从本地报告和对话中提炼通用经验；敏感原文、目标信息和账号不会提交到 Git。
- 核心功能只需要 Python 3.11+，不强制依赖 `uv` 或第三方扫描器。

## 安装与更新

克隆仓库后运行：

```bash
python scripts/update.py
```

以后更新使用：

```bash
blue-sec update
```

程序会检测本机已有的受支持客户端并安装同一份 Effective Skill。检查当前状态：

```bash
blue-sec-doctor
```

## 使用方法

安装后直接用自然语言向 Agent 说明任务，例如：

```text
对这个 Web 系统进行完整渗透测试，保存证据并持续验证所有高风险候选。
复测这份漏洞报告，区分已修复、仍存在和证据不足的项目。
分析这批日志和 PCAP，还原攻击路径并列出尚未确认的假设。
解包并分析这个 Electron ASAR，寻找攻击者输入到高权限能力的完整链路。
```

Agent 会自动选择对应 Skill。高风险线索不会让任务提前结束；未闭合的攻击链会保留为
候选并继续寻找前置条件，不能验证的部分会明确标为阻塞或未覆盖。

## 常用命令

```bash
blue-sec-doctor                         # 检查安装和能力状态
blue-sec-search '水平越权'              # 检索安全知识
blue-sec-report-ingest scan <报告目录>  # 索引本地安全报告
blue-sec-session-distill --source all  # 提炼本机可读取的安全会话
blue-sec-context status --workspace <任务目录>  # 检查任务记忆状态
blue-sec skill status                  # 查看当前 Effective Skill
```

第三方知识来源及许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
详细命令可运行 `blue-sec --help` 或对应子命令的 `--help`。
