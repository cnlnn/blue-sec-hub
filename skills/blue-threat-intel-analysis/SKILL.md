---
name: blue-threat-intel-analysis
description: 对攻击情报、IP、域名、URL、证书、哈希、邮箱、账号别名、恶意样本配置和公开线索做防御性关联与溯源分析。用于 IOC 规范化和富化、基础设施关系图、历史解析与证书关联、活动簇和攻击组织假设、情报时效判断、溯源置信度评估，以及生成封禁、监测和进一步取证线索。
---

# Threat Intelligence And Attribution

## Workflow

1. 保存原始情报及来源，记录首次/最后观察时间、发布时间、时区、采集方式和原始值；当前观测与历史情报分开。
2. 规范化 IP、域名、URL、证书指纹、文件哈希、账号和样本配置，去重但保留来源与时间范围。
3. 逐层富化：
   - 网络：ASN、网段、托管商、RDAP/WHOIS、地理与云/CDN/VPN/Tor 属性。
   - DNS/证书：A/AAAA/CNAME/NS/MX、历史解析、CT 日志、SAN、Issuer 和证书复用。
   - 内容/样本：网页特征、favicon、TLS、HTTP Header、C2 配置、代码/字符串和恶意家族。
   - 身份线索：公开账号、邮箱、仓库、签名和复用痕迹。
4. 构建带时间的关系图，每条边记录来源和类型，例如 `resolved-to`、`same-certificate`、`same-registrant`、`same-sample-config`、`observed-communicating`。
5. 分层给出结论：
   - 基础设施归属：谁运营或托管该资源。
   - 活动簇关联：哪些 IOC/样本/行为可能属于同一活动。
   - 威胁组织假设：与已知组织的 TTP 和基础设施重合程度。
   - 现实身份归属：需要多源独立证据，默认保持未知。
6. 单一 IP、同 ASN、同注册商、同国家、公开标签或时间接近不能独立证明同一攻击者。
7. 将流量证据交叉验证到 `blue-network-traffic-analysis`，样本交 `blue-malware-analysis`，事件路径交 `blue-incident-reconstruction`。
8. 涉及当前解析、注册、证书、声誉或最新情报时在线核对，明确查询时间；使用 `blue-local-knowledge` 搜索内部历史命中。

## Confidence

- `high`：多类独立证据在同一时间范围内闭环。
- `medium`：存在可靠关联，但仍有共享基础设施或数据陈旧等替代解释。
- `low`：单源标签、弱复用或未经验证的公开说法。
- `unknown`：证据不足，不做身份归属。

## Output

输出 IOC 表、来源与时效、基础设施/身份关系图、关键时间线、活动簇、置信度、替代解释、内部命中、检测封禁建议和下一步公开或内部取证线索。
