#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1
ACTIVE_SCOPES = {"global-security", "workflow", "project"}
POLICY_CATEGORIES = {
    "workflow-order",
    "completion-gate",
    "evidence-standard",
    "tool-policy",
    "safety-boundary",
    "output-contract",
    "interaction",
}

SECRET_PATTERNS = (
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(
        r"(?i)\b(?:authorization|cookie|set-cookie|x-api-key|api[-_]?key|"
        r"access[-_]?token|refresh[-_]?token|token|password|passwd|secret|sessionid)"
        r"\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.S,
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
TARGET_PATTERNS = (
    re.compile(r"https?://[^\s)\]>'\"]+", re.I),
    re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
    re.compile(r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b"),
    re.compile(
        r"/(?:api|rest|admin|internal|service|svc|v\d+)"
        r"(?:/[A-Za-z0-9_{}:.-]+)+",
        re.I,
    ),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.I),
    re.compile(
        r"(?:姓名|账号|用户|负责人|参与人)\s*[:：=]\s*[\u3400-\u9fff]{2,4}"
        r"|[赵钱孙李周吴郑王冯陈蒋沈韩杨朱秦许何吕张孔曹严华金魏陶姜谢邹苏潘葛范彭鲁韦马苗方袁柳史唐薛雷贺倪汤罗毕郝安常于傅齐康伍余顾孟黄萧尹姚邵汪毛米戴宋熊纪董梁杜阮蓝席季贾江郭梅林钟徐高夏蔡田樊胡霍万卢莫房陆翁段温庄阎廖刘叶黎乔谭曾][\u3400-\u9fff]{1,2}(?=的(?:账号|用户|权限|查询)|本人|自己|可见|或匿名|与匿名)",
        re.I,
    ),
    re.compile(
        r"(?:对象|用户|账号|订单|任务|工单|租户).{0,8}(?:ID|Id|id|编号)"
        r"\s*[:：=]\s*[A-Za-z0-9_-]{3,}",
        re.I,
    ),
    re.compile(
        r"(?<![A-Za-z0-9_])(?:participantUserRightId|participantId|woNo|urlKey|taskId|"
        r"objectId|accountId|customerId|tenantId|recordId|userId)(?![A-Za-z0-9_])",
        re.I,
    ),
)
DIRECTIVE_RE = re.compile(
    r"(?:必须|不要|不能|不得|需要|应该|应当|确保|默认|以后|每次|始终|"
    r"我希望|我不想|不用再|不允许|must|should|never|always|by default|"
    r"do not|don't|ensure|require)",
    re.I,
)
STABLE_RE = re.compile(
    r"(?:以后|每次|始终|永远|默认|不用再|不再|所有.*任务|"
    r"always|never|by default|every\s+(?:time|task))",
    re.I,
)
GENERALIZATION_RE = re.compile(
    r"(?:所有|任何|以后|每次|始终|默认|通用|普适|不止|不能只|"
    r"all\s+(?:tasks|targets|sites)|every\s+(?:time|task)|generali[sz])",
    re.I,
)
ONE_OFF_RE = re.compile(r"(?:本次|这次|临时|当前任务|for this (?:run|task))", re.I)
ARTIFACT_RE = re.compile(
    r"^(?:漏洞名称|漏洞描述|请求包|响应包|风险等级|修复建议|报告原文|日志内容)\s*[:：]",
    re.I,
)
REDACTED_TARGET_RE = re.compile(
    r"\[REDACTED_(?:URL|IP|DOMAIN|API_PATH|ID|PATH|EMAIL|PHONE|PERSON|TASK_FIELD)\]"
)
EXECUTION_PLAN_RE = re.compile(
    r"(?:^|\n)\s*(?:#{1,6}\s+|(?:PR|阶段|Phase)\s*\d+\b|\d+[.、]\s+)",
    re.I,
)
PLATFORM_POLICY_RE = re.compile(
    r"(?:update_goal|create_goal|request_user_input|tool namespace|valid channels|"
    r"developer message|system message|token budget|sandbox_permissions|"
    r"global user context|default reply language|source tree\s*->\s*white-box|"
    r"for security tasks:)",
    re.I,
)


CANONICAL_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "observable-surface-closure",
        "category": "completion-gate",
        "summary": "Resolve every currently observable route, control, API, object, state, and applicable test family as tested or not applicable with evidence; blockers remain interim and never satisfy complete coverage.",
        "pattern": re.compile(r"(?:信息收集|攻击面|路由|接口|功能点).{0,40}(?:全面|完整|不能漏|不漏测)|(?:全面|完整).{0,30}(?:测试|覆盖)", re.I),
    },
    {
        "id": "inventory-is-not-tested-coverage",
        "category": "completion-gate",
        "summary": "Keep discovered, current-validated, actually-tested, and blocked counts separate; inventory or a queued plan never satisfies test coverage.",
        "pattern": re.compile(r"(?:库存|发现数|路由数|接口数|计划|排队).{0,40}(?:不等于|不能.*(?:算|冒充)|不是).{0,20}(?:测试|覆盖|已测)", re.I),
    },
    {
        "id": "fresh-evidence-separated-from-history",
        "category": "evidence-standard",
        "summary": "Separate freshly collected evidence from historical reports; history may seed tests but cannot satisfy current coverage or confirm a current finding.",
        "pattern": re.compile(r"(?:新证据|本次证据|新采集).{0,30}(?:历史|旧证据)|(?:历史|旧报告).{0,30}(?:种子|不能.*(?:确认|覆盖|满足))", re.I),
    },
    {
        "id": "evidence-before-confirmation",
        "category": "evidence-standard",
        "summary": "Do not confirm a vulnerability from HTTP 200, a static endpoint string, scanner output, handler reachability, a validation error, or a random nonexistent identifier alone.",
        "pattern": re.compile(r"(?:HTTP.?200|静态.*接口|扫描器|随机.*ID|不存在.*ID|处理器可达|校验错误).{0,60}(?:不能|不得|不算|不是).{0,30}(?:漏洞|确认|越权)", re.I),
    },
    {
        "id": "single-account-authorization-decomposition",
        "category": "workflow-order",
        "summary": "A single account blocks only genuine cross-principal ownership checks; continue anonymous, low-privilege function, subject binding, self-owned object, protected-property, qualification, and state tests.",
        "pattern": re.compile(r"(?:一个|单).{0,8}(?:账号|账户).{0,40}(?:越权|授权).{0,60}(?:不能.*阻塞|不是.*都.*不能|继续|可以测)", re.I),
    },
    {
        "id": "collect-before-batched-validation",
        "category": "workflow-order",
        "summary": "Collect the observable SPA surface completely before extraction and batched validation; continue discovery until the route, resource, control, and request queues converge.",
        "pattern": re.compile(r"先.{0,12}(?:完整|全面)(?:提取|收集|采集).{0,20}(?:再|然后).{0,20}(?:抽取|分批|测试|验证)", re.I),
    },
    {
        "id": "url-first-default",
        "category": "interaction",
        "summary": "Accept a target URL as the default assessment input and collect the required assets automatically instead of requiring pre-collected files.",
        "pattern": re.compile(r"(?:只给|仅给|给).{0,12}(?:域名|URL|网址).{0,30}(?:直接|自动).{0,30}(?:测试|采集|收集|分析)", re.I),
    },
    {
        "id": "commandless-security-entrypoint",
        "category": "interaction",
        "summary": "Run the security workflow from natural-language requests without requiring the user to operate internal commands, ledgers, or authorization envelopes.",
        "pattern": re.compile(r"(?:不用|不想|不要).{0,20}(?:命令|维护|授权信封|JSON|分类表).{0,40}(?:直接|自动|调用|完成)|(?:用户|我).{0,20}(?:不需要|不用).{0,20}(?:运行|执行).{0,10}命令", re.I),
    },
    {
        "id": "native-runtime-only",
        "category": "tool-policy",
        "summary": "The core security workflow must use repository-native execution and must not install, download, invoke, or require third-party assessment tools.",
        "pattern": re.compile(r"(?:第三方|外部).{0,20}(?:工具|扫描器).{0,30}(?:不想|不要|不能|不得|不应).{0,20}(?:依赖|安装|调用|使用)|(?:不想|不要|不能|不得).{0,25}(?:skill|流程|核心).{0,20}依赖", re.I),
    },
    {
        "id": "generic-skill-no-target-specialization",
        "category": "workflow-order",
        "summary": "Promote only target-independent methods to shared Skills; keep domains, interfaces, accounts, object values, and deployment-specific conclusions in local evidence or candidates.",
        "pattern": re.compile(r"(?:skill|规则|方法).{0,35}(?:通用|普适|不能.*(?:站点|目标)|不只.*(?:站点|系统))", re.I),
    },
    {
        "id": "machine-state-survives-context-compaction",
        "category": "completion-gate",
        "summary": "Persist critical scope, evidence, findings, blockers, and unresolved work in machine state so context compaction or platform switching cannot lose them or repeat resolved work.",
        "pattern": re.compile(r"(?:上下文压缩|自动压缩|切换平台|重启).{0,40}(?:不能|防止|不要).{0,30}(?:丢|遗漏|重复|影响)", re.I),
    },
    {
        "id": "minimally-disruptive-validation",
        "category": "safety-boundary",
        "summary": "Prefer minimally disruptive validation, preserve originals, use self-owned reversible objects for writes, and require cleanup evidence.",
        "pattern": re.compile(r"(?:最小扰动|可逆|自有对象|保留原件|清理记录|回滚).{0,40}(?:必须|优先|需要|不能)", re.I),
    },
    {
        "id": "prerequisite-discovery-before-blocking",
        "category": "workflow-order",
        "summary": "When an ID, request shape, producer, consumer, business state, input sink, or cleanup action is missing, search current safe producers before blocking or concluding the test.",
        "pattern": re.compile(r"(?:(?:前提|ID|请求形状|生产者|消费者|业务状态|清理动作).{0,50}(?:缺失|缺少|没有|没找到)|(?:缺失|缺少|没有|没找到).{0,30}(?:前提|ID|请求形状|生产者|消费者|业务状态|清理动作)).{0,50}(?:继续|自动).{0,30}(?:发现|寻找|采集|挖掘|寻找)", re.I),
    },
    {
        "id": "sibling-path-generalization-audit",
        "category": "completion-gate",
        "summary": "When the user provides one example, audit the same state transition across sibling test families, Runner, Agent, Auditor, evidence, and reporting instead of patching only the named path.",
        "pattern": re.compile(r"(?:不要|不能).{0,20}(?:说什么|举.*例|点名).{0,30}(?:只改|只修)|(?:举一反三|同类.*一并|相邻.*一起)", re.I),
    },
)

CATEGORY_RULES = (
    ("completion-gate", re.compile(r"完成|覆盖|漏测|遗漏|全面|完整", re.I)),
    ("evidence-standard", re.compile(r"证据|确认|误报|历史|当前响应|对照|判定", re.I)),
    ("tool-policy", re.compile(r"工具|依赖|安装|执行器|MCP|浏览器", re.I)),
    ("safety-boundary", re.compile(r"范围|安全|破坏|回滚|清理|外带|高负载", re.I)),
    ("output-contract", re.compile(r"报告|输出|展示|统计|结论", re.I)),
    ("interaction", re.compile(r"不用.*命令|不想维护|直接|自动|傻瓜", re.I)),
)


def now() -> str:
    return datetime.now(UTC).isoformat()


def config_root() -> Path:
    value = os.environ.get("BLUE_SEC_CONFIG")
    if value:
        candidate = Path(value).expanduser()
        return candidate if candidate.suffix == "" else candidate.parent
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "blue-sec-hub"


def policy_path() -> Path:
    return config_root() / "operator-policy.json"


def stable_id(prefix: str, value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(raw).hexdigest()[:16]}"


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def redact_text(value: str, limit: int = 1000) -> tuple[str, int]:
    clean = value
    redactions = 0
    for pattern in SECRET_PATTERNS:
        clean, count = pattern.subn("[REDACTED_SECRET]", clean)
        redactions += count
    replacements = (
        (TARGET_PATTERNS[0], "[REDACTED_URL]"),
        (TARGET_PATTERNS[1], "[REDACTED_IP]"),
        (TARGET_PATTERNS[2], "[REDACTED_DOMAIN]"),
        (TARGET_PATTERNS[3], "[REDACTED_API_PATH]"),
        (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
        (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "[REDACTED_PHONE]"),
        (re.compile(r"(?:/home|/opt|/mnt|[A-Za-z]:\\)[^\s)\]>'\"]+"), "[REDACTED_PATH]"),
        (TARGET_PATTERNS[4], "[REDACTED_ID]"),
        (TARGET_PATTERNS[5], "[REDACTED_PERSON]"),
        (TARGET_PATTERNS[6], "[REDACTED_ID]"),
        (TARGET_PATTERNS[7], "[REDACTED_TASK_FIELD]"),
    )
    for pattern, replacement in replacements:
        clean, count = pattern.subn(replacement, clean)
        redactions += count
    return re.sub(r"\s+", " ", clean).strip()[:limit], redactions


def contains_target(value: str) -> bool:
    plan_markers = len(EXECUTION_PLAN_RE.findall(value))
    return plan_markers >= 3 or bool(REDACTED_TARGET_RE.search(value)) or any(
        pattern.search(value) for pattern in TARGET_PATTERNS
    )


def span_context(value: str, start: int, end: int) -> str:
    left = max(value.rfind(separator, 0, start) for separator in ("\n", "。", "！", "？", ";", "；"))
    right_candidates = [
        position
        for separator in ("\n", "。", "！", "？", ";", "；")
        if (position := value.find(separator, end)) >= 0
    ]
    right = min(right_candidates, default=len(value))
    return value[left + 1 : right]


def visible_directive_text(value: str) -> str:
    without_fences = re.sub(r"```.*?```", " ", value, flags=re.S)
    return "\n".join(
        line
        for line in without_fences.splitlines()
        if not line.lstrip().startswith(">") and not ARTIFACT_RE.search(line.strip())
    )


def category_for(value: str) -> str:
    return next((name for name, pattern in CATEGORY_RULES if pattern.search(value)), "workflow-order")


def scope_for(value: str, target_specific: bool) -> str:
    if target_specific:
        return "target"
    if ONE_OFF_RE.search(value):
        return "one-off"
    if re.search(r"(?:项目|仓库|代码库|project|repository|repo)", value, re.I):
        return "project"
    if STABLE_RE.search(value):
        return "global-security"
    return "workflow"


def extract_operator_candidates(
    value: str,
    *,
    source_session_hash: str,
    source_turn_ref: str,
    observed_at: str | None = None,
    validated: bool = False,
) -> list[dict[str, Any]]:
    redacted, _ = redact_text(value, max(1000, len(value)))
    text = visible_directive_text(redacted)
    if PLATFORM_POLICY_RE.search(text) or not DIRECTIVE_RE.search(text):
        return []
    observed_at = observed_at or now()
    results: list[dict[str, Any]] = []
    matched_spans: list[tuple[int, int]] = []
    for rule in CANONICAL_RULES:
        match = rule["pattern"].search(text)
        if not match:
            continue
        matched_spans.append(match.span())
        context = span_context(text, *match.span())
        explicit = bool(STABLE_RE.search(context) or re.search(r"(?:必须|不得|不允许|确保|我不想)", context, re.I))
        target_specific = bool(
            contains_target(context) and not GENERALIZATION_RE.search(context)
        )
        results.append(
            {
                "schema_version": SCHEMA_VERSION,
                "policy_id": f"operator-{rule['id']}",
                "policy_key": rule["id"],
                "category": rule["category"],
                "scope": scope_for(context, target_specific),
                "summary": rule["summary"],
                "value": "required",
                "source_session_hash": source_session_hash,
                "source_turn_ref": source_turn_ref,
                "observed_at": observed_at,
                "explicit_stable": explicit,
                "validation_state": "validated" if validated else "stated",
                "policy_origin": "canonical",
                "target_specific": target_specific,
                "state": "candidate",
            }
        )
    clauses = re.split(r"(?<=[。！？!?;；])|\n", text)
    for clause in clauses:
        clause = clause.strip(" -\t\r\n")
        if not clause or not DIRECTIVE_RE.search(clause):
            continue
        if any(start <= text.find(clause) < end for start, end in matched_spans):
            continue
        # Free-form directives stay in the task transcript. Persisting one
        # review object per clause created a noisy pseudo-policy backlog and
        # retained no reusable behavior beyond the already redacted excerpt.
        # A separate learning review must first turn one into a canonical rule.
        continue
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for item in results:
        unique[(item["policy_key"], item["summary"])] = item
    return list(unique.values())


def resolve_policy_candidates(
    candidates: Iterable[dict[str, Any]],
    destination: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in candidates:
        grouped[(str(item["policy_key"]), str(item.get("value", "required")))].append(item)
    resolved: list[dict[str, Any]] = []
    for (policy_key, value), occurrences in grouped.items():
        occurrences.sort(key=lambda item: (str(item.get("observed_at", "")), item["policy_id"]))
        latest = dict(occurrences[-1])
        sessions = {str(item.get("source_session_hash")) for item in occurrences}
        validated = sum(item.get("validation_state") == "validated" for item in occurrences)
        explicit = any(bool(item.get("explicit_stable")) for item in occurrences)
        origin = str(latest.get("policy_origin", "canonical"))
        if origin == "canonical":
            # Canonicalization removes target details, but durable policy still
            # needs two independently validated scenarios.
            high_confidence = bool(explicit and len(sessions) >= 2 and validated >= 2)
        else:
            # Free-form directives remain target-local until a separate
            # learning review turns them into a canonical rule.
            high_confidence = False
        active = bool(
            latest.get("scope") in ACTIVE_SCOPES
            and not latest.get("target_specific")
            and high_confidence
        )
        latest.update(
            {
                "policy_id": f"operator-{policy_key}" if not policy_key.startswith("custom-") else latest["policy_id"],
                "occurrences": len(occurrences),
                "independent_sessions": len(sessions),
                "validated_occurrences": validated,
                "explicit_stable": explicit,
                "state": "active" if active else "review",
                "source_refs": sorted({str(item["source_turn_ref"]) for item in occurrences})[:100],
            }
        )
        resolved.append(latest)
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in resolved:
        by_key[item["policy_key"]].append(item)
    conflicts: list[dict[str, Any]] = []
    for policy_key, values in by_key.items():
        distinct_values = {item.get("value") for item in values}
        if len(distinct_values) <= 1:
            continue
        values.sort(key=lambda item: str(item.get("observed_at", "")))
        winner = values[-1]
        for item in values[:-1]:
            item["state"] = "superseded"
            item["superseded_by"] = winner["policy_id"]
        conflicts.append(
            {
                "schema_version": SCHEMA_VERSION,
                "policy_key": policy_key,
                "values": sorted(str(value) for value in distinct_values),
                "resolution": "latest-explicit-user-requirement",
                "active_policy_id": winner["policy_id"],
            }
        )
    active = sorted(
        (item for item in resolved if item["state"] == "active"),
        key=lambda item: (item["category"], item["policy_key"]),
    )
    store = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now(),
        "precedence": [
            "current-explicit-user-instruction",
            "repository-AGENTS-policy",
            "project-operator-policy",
            "global-security-operator-policy",
            "skill-default",
        ],
        "host_policy_always_wins": True,
        "active": active,
        "review_count": sum(item["state"] == "review" for item in resolved),
        "superseded_count": sum(item["state"] == "superseded" for item in resolved),
        "policy_digest": hashlib.sha256(
            json.dumps(
                [(item["policy_id"], item["summary"]) for item in active],
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
    }
    if destination is not None:
        atomic_json(destination, store)
    return store, sorted(resolved, key=lambda item: item["policy_id"]), conflicts


def load_active_policy_context(workflow: str = "web-api", limit: int = 24) -> dict[str, Any]:
    path = policy_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": SCHEMA_VERSION, "policy_digest": None, "rules": []}
    rules = []
    for item in value.get("active", []):
        if item.get("scope") not in ACTIVE_SCOPES:
            continue
        rules.append(
            {
                "id": item.get("policy_id"),
                "category": item.get("category"),
                "summary": item.get("summary"),
            }
        )
        if len(rules) >= limit:
            break
    return {
        "schema_version": SCHEMA_VERSION,
        "workflow": workflow,
        "policy_digest": value.get("policy_digest"),
        "rules": rules,
    }
