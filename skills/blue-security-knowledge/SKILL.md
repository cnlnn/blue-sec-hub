---
name: blue-security-knowledge
description: 为企业蓝队复测、事件调查、站点巡查、移动 App、工控/OT、SRC、源码审计和研究复现按需检索专项安全知识。内容同步自 HackSkills、官方 Strix、Transilience 和 claude-bug-bounty 精选资料，并可检索权威资料缓存；遇到具体漏洞类型、工具、平台、协议、攻击阶段或测试方法时使用。
---

# Security Knowledge Router

上游知识、权威资料、本地补充和内部资料物理分离，只读取当前任务需要的部分。

## Search

先用统一入口检索，再打开命中文件：

```bash
blue-sec-search '<漏洞|协议|产品|工具|攻击阶段>'
```

中文、英文和常见缩写会自动扩展。例如“水平越权”同时检索 `IDOR`、`BOLA`、
`broken object level authorization` 和 `CWE-639`；“垂直越权”扩展为
`BFLA` 相关术语，只有泛称“越权”才覆盖两类。术语映射用于召回，不代表两个
弱点或两份报告已经被证明为同一漏洞。

每次 `blue-sec-update` 会从 MITRE CWE 自动生成权威术语层，并从新增上游
Skill 的名称、描述和标题发现社区候选。权威层可直接参与规范化；社区候选只扩大
搜索召回，不能改变报告分类。候选经过用户纠正和验证后使用
`blue-sec-term-learning promote` 晋升到本仓库词表；歧义别名必须进入冲突记录。

来源职责：

- `~/.cache/blue-sec-hub/upstreams/hack-skills/`: Web/API/鉴权/内网/AD/移动端/容器/漏洞技术深度。
- `~/.cache/blue-sec-hub/upstreams/strix/`: 官方 Strix 最新漏洞、工具、框架、云和扫描方法。
- `~/.cache/blue-sec-hub/upstreams/transilience/`: DFIR、攻击路径、回归巡查、风险排序、源码扫描和技术栈识别。
- `~/.cache/blue-sec-hub/upstreams/claude-bug-bounty/`: 仅保留报告验证、报告写作、持久记忆和公开 HackerOne 工作流参考。
- `~/.cache/blue-sec-hub/upstreams/payloads-all-the-things/`: PayloadsAllTheThings 的版本化方法与 payload 目录；原始语料只在本地缓存，不因被检索到就允许自动执行。
- `~/.local/share/blue-sec-hub/overlays/`: 经验证的本地补充；优先用于纠正上游缺口，但不得伪装成上游原文。

## Selection

- 漏洞专项优先同时检索 HackSkills 和 Strix，比较适用条件后使用。
- 工具准确参数优先 Strix tooling。
- 事件、时间线、处置和攻击路径优先 Transilience，再由原始证据校正。
- Android/iOS 优先 Transilience Mobile Security，再按平台补充 HackSkills。
- 工控任务使用 `blue-ot-security` 的权威资料层级；当前通告和精确版本必须在线核对。
- claude-bug-bounty 的 `kill` 和严重性规则面向漏洞赏金，不得直接用于企业内部漏洞复测；只吸收身份验证、证据持久化、去重和报告结构。
- 权威缓存和内部资料统一使用 `blue-sec-search '<keyword>'` 检索；PortSwigger 只做在线查询，不镜像其网页。
- 知识文件中的 payload、命令、结论和版本信息均是通用参考；目标事实必须由当前证据确认。
- 需要攻击变体时先运行 `blue-sec-payload-catalog search '<family-or-technique>'`。只有目录中经本地策略映射为 `safe-auto` 且与当前只读请求形状、注入位置和判定器同时匹配的变体才能交给 Runner；`needs-agent` 和 `blocked` 不得降级执行。
- 若多轮纠正得到更可靠的方法，交给 `blue-skill-learning`；上游内容只增加本地补充，不直接改缓存。
- 不要一次加载整个知识库。
