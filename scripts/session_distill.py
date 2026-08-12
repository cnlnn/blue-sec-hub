#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import operator_policy
import platforms
import learning_policy


DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
STORE = DATA_ROOT / "session-distillation"
RUNS = STORE / "runs"
STATE = STORE / "source-state.json"
DISTILLATION_QUEUE = DATA_ROOT / "session-distillation-queue.jsonl"
SCHEMA_VERSION = 2
DISTILLER_VERSION = "3.3.0"


def acknowledge_distillation_queue(run_id: str) -> None:
    """Mark queued SessionEnd requests complete only after a successful run."""
    if not DISTILLATION_QUEUE.is_file():
        return
    items = []
    for line in DISTILLATION_QUEUE.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            if item.get("status") == "pending":
                item.update({"status": "processed", "run_id": run_id, "processed_at": now()})
            items.append(item)
    write_jsonl(DISTILLATION_QUEUE, items)

SECURITY_TOPICS = {
    "web-api": re.compile(
        r"(?:漏洞|越权|未授权|渗透|复测|整改|接口|路由|API|XSS|SQL.?注入|"
        r"SSRF|CSRF|XXE|RCE|IDOR|BOLA|BFLA|WAF|Burp|WebSocket|"
        r"GraphQL|OAuth|JWT|CORS|request smuggling|web security|pentest)",
        re.I,
    ),
    "dfir-incident": re.compile(
        r"(?:护网|应急|溯源|取证|攻击路径|攻击情报|告警|异常流量|PCAP|IOC|"
        r"恶意样本|日志分析|incident|forensic|threat intel|malware)",
        re.I,
    ),
    "mobile-reverse": re.compile(
        r"(?:APK|AAB|IPA|Android|iOS|Frida|JADX|逆向|脱壳|WebView|移动端安全)",
        re.I,
    ),
    "ot-infrastructure": re.compile(
        r"(?:工控|工业控制|ICS|SCADA|PLC|RTU|HMI|主机基线|中间件|数据库安全|"
        r"防火墙|容器安全|Kubernetes|Active Directory|域渗透)",
        re.I,
    ),
    "security-tooling": re.compile(
        r"(?:Strix|Metasploit|sqlmap|ffuf|gobuster|PayloadsAllTheThings|"
        r"安全扫描|漏洞扫描|攻击面|security skill|blue-sec-hub)",
        re.I,
    ),
    "source-security": re.compile(
        r"(?:代码审计|白盒审计|source code security|SAST|污点分析|CWE-|CVE-)",
        re.I,
    ),
}
NEGATIVE_SIGNAL = re.compile(
    r"(?:遗漏|漏测|没测|没有发现|不全面|不完整|不对|错误|误报|根本没|只能找到|"
    r"应该|必须|以后不能|需要优化|需要改进|通用|普适|为什么.*没)",
    re.I,
)
ACCEPTANCE_SIGNAL = re.compile(
    r"(?:这样就对|现在可以|已经解决|验证通过|测试通过|结果正确|修好了|可以了|"
    r"符合预期|passed|all tests pass)",
    re.I,
)
VERIFIED_SIGNAL = re.compile(
    r"(?:测试|验证|回归|fixture|unit test|integration).{0,40}"
    r"(?:通过|成功|passed|\bok\b)|(?:通过|成功|passed).{0,40}(?:测试|验证|回归)",
    re.I,
)
TARGET_SIGNAL = re.compile(
    r"https?://|(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)|"
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+(?:com|cn|net|org|io|gov|test)\b|"
    r"/(?:api|rest|admin|internal|service|svc|v\d+)(?:/[A-Za-z0-9_{}:.-]+)+|"
    r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b",
    re.I,
)
GENERIC_CONCEPTS = {
    "route-coverage": re.compile(r"(?:路由|页面|route|lazy chunk|微前端)", re.I),
    "api-discovery": re.compile(r"(?:接口|API|请求形状|假.?200|404|fallback)", re.I),
    "authorization": re.compile(r"(?:越权|授权|IDOR|BOLA|BFLA|主体绑定|租户)", re.I),
    "evidence": re.compile(r"(?:证据|正负对照|HTTP.?200|误报|判定|oracle)", re.I),
    "business-state": re.compile(r"(?:状态|资格|配额|审批|生命周期|业务逻辑)", re.I),
    "file-parser": re.compile(r"(?:上传|文件|解析|压缩包|导入|导出|XXE)", re.I),
    "input-validation": re.compile(r"(?:注入|XSS|SQL|命令执行|payload|解析差异)", re.I),
    "session": re.compile(r"(?:登录态|会话|Token|JWT|Cookie|认证)", re.I),
    "traffic-tool": re.compile(r"(?:Burp|PCAP|流量|HAR|Playwright|MCP)", re.I),
    "safety": re.compile(r"(?:清理|回滚|破坏|高负载|外带|安全边界)", re.I),
}
LEARNING_SECURITY_CORRECTION = re.compile(
    r"(?:渗透|漏洞|复测|误报|漏测|攻击链|攻击面|越权|未授权|证据(?:门槛|状态|链)?|"
    r"前提(?:闭合|来源)?|登录态|会话状态|Burp|HAR|PCAP|扫描器|安全结论|"
    r"(?:XSS|SSRF|CSRF|XXE|RCE|SQL|命令)\s*(?:注入|执行|漏洞|风险)?|"
    r"authorization|authentication|exploit|finding|false.?positive)",
    re.I,
)
INTERNAL_CONTEXT_MARKER = re.compile(r"<codex_internal_context\b", re.I)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def stable_id(prefix: str, value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return f"{prefix}-{digest(raw)[:16]}"


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


def write_jsonl(path: Path, values: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for value in values:
            handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def sanitize(value: str, limit: int = 360) -> tuple[str, int]:
    return operator_policy.redact_text(value, limit)


def learning_excerpt(value: str, target_specific: bool, limit: int = 280) -> str:
    """Return a bounded review excerpt without retaining deployment material."""
    if target_specific:
        return "[TARGET_SPECIFIC_CONTENT_WITHHELD]"
    clean, _ = sanitize(value, limit)
    clean = re.sub(r"```.*?```", "[CODE_BLOCK_WITHHELD]", clean, flags=re.S)
    clean = re.sub(r"\s+", " ", clean).strip()
    if (
        operator_policy.contains_target(clean)
        or TARGET_SIGNAL.search(clean)
        or learning_policy.target_specific_findings(clean)
    ):
        return "[TARGET_SPECIFIC_CONTENT_WITHHELD]"
    return clean[:limit]


def withhold_target_context(turns: list[dict[str, Any]]) -> None:
    """Prevent short target aliases from surviving in paired assistant excerpts."""
    for index, turn in enumerate(turns):
        if turn.get("role") != "user" or not turn.get("target_signal"):
            continue
        turn["learning_excerpt"] = "[TARGET_SPECIFIC_CONTENT_WITHHELD]"
        for following in turns[index + 1 : index + 9]:
            if following.get("role") == "user":
                break
            if following.get("role") == "assistant":
                following["learning_excerpt"] = "[TARGET_SPECIFIC_CONTENT_WITHHELD]"
                break


PAYLOAD_BLOCK_RE = re.compile(r"```(?:[^\n`]*)\n(.*?)```", re.S)
PAYLOAD_LINE_RE = re.compile(
    r"(?im)^\s*(?:payload|test input|测试载荷|测试输入)\s*[:：]\s*(.{1,500})$"
)
PAYLOAD_FAMILIES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("browser-content.xss-dom-richtext", re.compile(r"<script|onerror\s*=|javascript:|<svg|data-blue-sec", re.I), "browser-no-network-marker"),
    ("injection.sql-nosql-orm", re.compile(r"(?:'|\")\s*(?:or|and)\s+\d+\s*=\s*\d+|\$ne\b|\$where\b", re.I), "boolean-response-differential"),
    ("injection.xml-ldap-xpath", re.compile(r"<!DOCTYPE|<!ENTITY|\(\|\(|xpath|ldap", re.I), "parser-response-differential"),
    ("files-data-export.path-read-download", re.compile(r"\.\.[/\\]", re.I), "path-response-differential"),
    ("api-protocol.parameter-encoding", re.compile(r"%0d%0a|%2e%2e|;\.(?:js|css|html)", re.I), "protocol-normalization-differential"),
)
PAYLOAD_BLOCKED_RE = re.compile(
    r"reverse.?shell|webshell|/bin/(?:ba)?sh|cmd\.exe|powershell|nc\s+-e|"
    r"bash\s+-i|rm\s+-rf|drop\s+table|shutdown|fork.?bomb|credential|"
    r"mimikatz|meterpreter|processbuilder|runtime\.getruntime",
    re.I,
)
PAYLOAD_AGENT_RE = re.compile(
    r"dnslog|interactsh|callback|webhook|/etc/passwd|win\.ini|"
    r"sleep\s*\(|benchmark\s*\(|waitfor\s+delay|union\s+select|"
    r"(?:insert|update|delete)\s+(?:into|from|\w+)",
    re.I,
)


def payload_candidates(
    value: str,
    *,
    source_session_hash: str,
    source_turn_ref: str,
    observed_at: str | None,
) -> list[dict[str, Any]]:
    segments = [match.group(1) for match in PAYLOAD_BLOCK_RE.finditer(value)]
    segments.extend(match.group(1) for match in PAYLOAD_LINE_RE.finditer(value))
    results: list[dict[str, Any]] = []
    for segment in segments:
        candidate = segment.strip()
        if not candidate or len(candidate) > 1000:
            continue
        family = next(
            ((name, oracle) for name, pattern, oracle in PAYLOAD_FAMILIES if pattern.search(candidate)),
            None,
        )
        if not family:
            continue
        sanitized, redactions = sanitize(candidate, 400)
        blocked = bool(PAYLOAD_BLOCKED_RE.search(candidate))
        agent = bool(PAYLOAD_AGENT_RE.search(candidate) or operator_policy.contains_target(candidate))
        policy = "blocked" if blocked else "needs-agent" if agent else "safe-auto"
        payload_hash = digest(candidate.encode("utf-8", errors="replace"))
        value_record: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "candidate_id": stable_id("session-payload", [family[0], payload_hash]),
            "family": family[0],
            "payload_sha256": payload_hash,
            "payload_policy": policy,
            "oracle_id": family[1],
            "binding_requirements": [
                "observed-request-shape",
                "known-parameter-position",
                "normal-baseline",
                "single-variable-variant",
                "repeatable-differential",
            ],
            "source_session_hash": source_session_hash,
            "source_turn_ref": source_turn_ref,
            "observed_at": observed_at or now(),
            "redactions": redactions,
            "validation_state": "unverified",
            "state": "candidate",
        }
        if policy != "blocked" and "[REDACTED_SECRET]" not in sanitized:
            value_record["payload_template"] = sanitized
        results.append(value_record)
    return results


def content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") in {"input_text", "output_text", "text"}:
            parts.append(str(item.get("text") or ""))
    return "\n".join(parts)


def argument_keys(value: Any) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(value, dict):
        return []
    return sorted(str(key) for key in value)[:100]


def verification_tool_call(value: Any) -> bool:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return False
    if not isinstance(value, dict):
        return False
    command = str(value.get("cmd") or value.get("command") or "")
    return bool(
        re.search(
            r"(?:pytest|unittest|go\s+test|cargo\s+test|npm\s+test|pnpm\s+test|"
            r"scripts/validate\.py|\bvalidate\b|\blint\b|\bbuild\b)",
            command,
            re.I,
        )
    )


def tool_result_metadata(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {"output_type": "text", "output_sha256": digest(value.encode())}
    result: dict[str, Any] = {"output_type": type(value).__name__}
    if isinstance(value, dict):
        for key in ("exit_code", "status", "isError", "returncode"):
            if key in value and isinstance(value[key], (str, int, bool, type(None))):
                result[key] = value[key]
        result["field_names"] = sorted(str(key) for key in value)[:60]
    return result


def classify_candidate(text: str) -> str:
    choices = (
        ("coverage-gap", r"(?:遗漏|漏测|不全面|路由|页面|接口|攻击面)"),
        ("false-positive-rule", r"(?:误报|假.?200|fallback|错误拼接|不存在)"),
        ("evidence-oracle", r"(?:证据|判定|HTTP.?200|正负对照|可重复|oracle)"),
        ("tool-integration", r"(?:Burp|Playwright|MCP|Strix|执行器|工具)"),
        ("safety-rule", r"(?:清理|回滚|破坏|高负载|外带|安全边界)"),
        ("vulnerability-pattern", r"(?:越权|注入|XSS|SSRF|CSRF|XXE|RCE|漏洞类型|payload)"),
    )
    for name, pattern in choices:
        if re.search(pattern, text, re.I):
            return name
    return "workflow-rule"


def concepts_for(text: str) -> list[str]:
    return sorted(name for name, pattern in GENERIC_CONCEPTS.items() if pattern.search(text))


def topics_for(text: str) -> list[str]:
    return sorted(name for name, pattern in SECURITY_TOPICS.items() if pattern.search(text))


def parse_session(path: Path, sha256: str, platform: str = "codex") -> dict[str, Any]:
    visible: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    operator_candidates: list[dict[str, Any]] = []
    session_payloads: list[dict[str, Any]] = []
    session_ids: set[str] = set()
    parents: set[str] = set()
    event_hashes: set[str] = set()
    duplicate_events = 0
    parse_errors = 0
    line_count = 0
    redactions = 0
    event_types: Counter[str] = Counter()
    call_hints: dict[str, bool] = {}
    with path.open("rb") as handle:
        for number, raw in enumerate(handle, start=1):
            line_count = number
            event_hash = digest(raw.rstrip(b"\r\n"))
            if event_hash in event_hashes:
                duplicate_events += 1
                continue
            event_hashes.add(event_hash)
            try:
                event = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                parse_errors += 1
                continue
            event_type = str(event.get("type") or "unknown")
            event_types[event_type] += 1
            if platform == "claude":
                if event.get("sessionId"):
                    session_ids.add(str(event["sessionId"]))
                if "subagents" in path.parts:
                    parents.add(str(path.parent.parent.name))
                if event_type not in {"user", "assistant"} or event.get("isMeta"):
                    continue
                message = event.get("message") if isinstance(event.get("message"), dict) else {}
                role = str(message.get("role") or event_type)
                content = message.get("content")
                raw_text = content_text(content)
                if raw_text:
                    clean, count = sanitize(raw_text)
                    redactions += count
                    turn_id = stable_id("turn", [sha256, number, role])
                    observed_at = str(event.get("timestamp") or event.get("createdAt") or "") or None
                    target_specific = bool(
                        TARGET_SIGNAL.search(raw_text)
                        or operator_policy.contains_target(raw_text)
                    )
                    visible.append(
                        {
                            "id": turn_id,
                            "event_sha256": event_hash,
                            "line": number,
                            "role": role,
                            "observed_at": observed_at,
                            "text_sha256": digest(raw_text.encode("utf-8", errors="replace")),
                            "target_signal": target_specific,
                            "learning_excerpt": learning_excerpt(raw_text, target_specific),
                            "topics": topics_for(raw_text),
                            "concepts": concepts_for(raw_text),
                            "negative_signal": bool(NEGATIVE_SIGNAL.search(raw_text)),
                            "acceptance_signal": bool(ACCEPTANCE_SIGNAL.search(raw_text)),
                            "verified_signal": bool(VERIFIED_SIGNAL.search(raw_text)),
                            "candidate_type": classify_candidate(raw_text),
                            "learning_security_signal": bool(
                                LEARNING_SECURITY_CORRECTION.search(raw_text)
                                and not INTERNAL_CONTEXT_MARKER.search(raw_text)
                            ),
                            "redactions": count,
                        }
                    )
                    if role == "user":
                        operator_candidates.extend(
                            operator_policy.extract_operator_candidates(
                                raw_text,
                                source_session_hash=digest(sha256.encode()),
                                source_turn_ref=turn_id,
                                observed_at=observed_at,
                            )
                        )
                    extracted_payloads = payload_candidates(
                            raw_text,
                            source_session_hash=digest(sha256.encode()),
                            source_turn_ref=turn_id,
                            observed_at=observed_at,
                        )
                    for item in extracted_payloads:
                        item["source_line"] = number
                    session_payloads.extend(extracted_payloads)
                blocks = content if isinstance(content, list) else []
                for block in blocks:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_use":
                        call_id = str(block.get("id") or "")
                        arguments = block.get("input")
                        hint = verification_tool_call(arguments)
                        if call_id:
                            call_hints[call_id] = hint
                        tools.append(
                            {
                                "line": number,
                                "kind": "call",
                                "name": str(block.get("name") or "unknown"),
                                "argument_fields": argument_keys(arguments),
                                "call_id_hash": digest(call_id.encode()) if call_id else None,
                                "verification_hint": hint,
                            }
                        )
                    elif block.get("type") == "tool_result":
                        call_id = str(block.get("tool_use_id") or "")
                        tools.append(
                            {
                                "line": number,
                                "kind": "result",
                                "call_id_hash": digest(call_id.encode()) if call_id else None,
                                "verification_hint": call_hints.get(call_id, False),
                                **tool_result_metadata(block.get("content")),
                            }
                        )
                continue
            payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
            if event_type == "session_meta":
                for key in ("id", "session_id"):
                    if payload.get(key):
                        session_ids.add(str(payload[key]))
                if payload.get("parent_thread_id"):
                    parents.add(str(payload["parent_thread_id"]))
                continue
            if event_type != "response_item":
                continue
            item_type = str(payload.get("type") or "")
            if item_type == "message" and payload.get("role") in {"user", "assistant"}:
                raw_text = content_text(payload.get("content"))
                if not raw_text:
                    continue
                clean, count = sanitize(raw_text)
                redactions += count
                role = str(payload["role"])
                turn_id = stable_id("turn", [sha256, number, role])
                observed_at = str(event.get("timestamp") or payload.get("timestamp") or "") or None
                target_specific = bool(
                    TARGET_SIGNAL.search(raw_text)
                    or operator_policy.contains_target(raw_text)
                )
                visible.append(
                    {
                        "id": turn_id,
                        "event_sha256": event_hash,
                        "line": number,
                        "role": role,
                        "observed_at": observed_at,
                        "text_sha256": digest(raw_text.encode("utf-8", errors="replace")),
                        "target_signal": target_specific,
                        "learning_excerpt": learning_excerpt(raw_text, target_specific),
                        "topics": topics_for(raw_text),
                        "concepts": concepts_for(raw_text),
                        "negative_signal": bool(NEGATIVE_SIGNAL.search(raw_text)),
                        "acceptance_signal": bool(ACCEPTANCE_SIGNAL.search(raw_text)),
                        "verified_signal": bool(VERIFIED_SIGNAL.search(raw_text)),
                        "candidate_type": classify_candidate(raw_text),
                        "learning_security_signal": bool(
                            LEARNING_SECURITY_CORRECTION.search(raw_text)
                            and not INTERNAL_CONTEXT_MARKER.search(raw_text)
                        ),
                        "redactions": count,
                    }
                )
                if role == "user":
                    operator_candidates.extend(
                        operator_policy.extract_operator_candidates(
                            raw_text,
                            source_session_hash=digest(sha256.encode()),
                            source_turn_ref=turn_id,
                            observed_at=observed_at,
                        )
                    )
                extracted_payloads = payload_candidates(
                        raw_text,
                        source_session_hash=digest(sha256.encode()),
                        source_turn_ref=turn_id,
                        observed_at=observed_at,
                    )
                for item in extracted_payloads:
                    item["source_line"] = number
                session_payloads.extend(extracted_payloads)
            elif item_type in {"function_call", "custom_tool_call"}:
                call_id = str(payload.get("call_id") or payload.get("id") or "")
                arguments = payload.get("arguments") or payload.get("input")
                verification_hint = verification_tool_call(arguments)
                if call_id:
                    call_hints[call_id] = verification_hint
                tools.append(
                    {
                        "line": number,
                        "kind": "call",
                        "name": str(payload.get("name") or payload.get("tool_name") or "unknown"),
                        "argument_fields": argument_keys(arguments),
                        "call_id_hash": digest(call_id.encode()) if call_id else None,
                        "verification_hint": verification_hint,
                    }
                )
            elif item_type in {"function_call_output", "custom_tool_call_output"}:
                call_id = str(payload.get("call_id") or payload.get("id") or "")
                tools.append(
                    {
                        "line": number,
                        "kind": "result",
                        "call_id_hash": digest(call_id.encode()) if call_id else None,
                        "verification_hint": call_hints.get(call_id, False),
                        **tool_result_metadata(payload.get("output")),
                    }
                )
    topic_counts = Counter(topic for item in visible for topic in item["topics"])
    user_security = sum(bool(item["topics"]) for item in visible if item["role"] == "user")
    all_security = sum(bool(item["topics"]) for item in visible)
    if not event_hashes or (parse_errors and not visible and not session_ids):
        classification = "error"
        reasons = ["no-parseable-session-content"]
    elif user_security >= 2 or (user_security >= 1 and all_security >= 2):
        classification = "security"
        reasons = ["repeated-user-security-intent"]
    elif user_security == 1 or all_security >= 2:
        classification = "ambiguous"
        reasons = ["limited-or-assistant-only-security-signal"]
    else:
        classification = "non-security"
        reasons = ["no-material-security-intent"]
    if parse_errors:
        reasons.append("contains-invalid-jsonl-records")
    return {
        "schema_version": SCHEMA_VERSION,
        "source_platform": platform,
        "source_id": stable_id("session-source", sha256),
        "sha256": sha256,
        "classification": classification,
        "classification_reasons": reasons,
        "session_ids": sorted(session_ids),
        "parent_thread_ids": sorted(parents),
        "topics": dict(sorted(topic_counts.items())),
        "line_count": line_count,
        "parse_errors": parse_errors,
        "duplicate_events": duplicate_events,
        "event_types": dict(sorted(event_types.items())),
        "visible_turns": visible,
        "tool_summaries": tools,
        "operator_candidates": operator_candidates,
        "payload_candidates": session_payloads,
        "redactions": redactions,
    }


def parse_hermes_session(path: Path, sha256: str, platform: str = "hermes") -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        document = {}
    messages = document.get("messages", []) if isinstance(document.get("messages"), list) else []
    visible = []
    operator_candidates = []
    session_payloads = []
    redactions = 0
    for number, message in enumerate(messages, start=1):
        if not isinstance(message, dict) or message.get("role") not in {"user", "assistant"}:
            continue
        raw_text = content_text(message.get("content"))
        if not raw_text:
            continue
        _, count = sanitize(raw_text)
        redactions += count
        role = str(message["role"])
        event_hash = digest(json.dumps(message, ensure_ascii=False, sort_keys=True).encode())
        turn_id = stable_id("turn", [sha256, number, role])
        observed_at = str(document.get("last_updated") or document.get("session_start") or "") or None
        target_specific = bool(
            TARGET_SIGNAL.search(raw_text)
            or operator_policy.contains_target(raw_text)
        )
        visible.append({
            "id": turn_id,
            "event_sha256": event_hash,
            "line": number,
            "role": role,
            "observed_at": observed_at,
            "text_sha256": digest(raw_text.encode("utf-8", errors="replace")),
            "target_signal": target_specific,
            "learning_excerpt": learning_excerpt(raw_text, target_specific),
            "topics": topics_for(raw_text),
            "concepts": concepts_for(raw_text),
            "negative_signal": bool(NEGATIVE_SIGNAL.search(raw_text)),
            "acceptance_signal": bool(ACCEPTANCE_SIGNAL.search(raw_text)),
            "verified_signal": bool(VERIFIED_SIGNAL.search(raw_text)),
            "candidate_type": classify_candidate(raw_text),
            "learning_security_signal": bool(
                LEARNING_SECURITY_CORRECTION.search(raw_text)
                and not INTERNAL_CONTEXT_MARKER.search(raw_text)
            ),
            "redactions": count,
        })
        if role == "user":
            operator_candidates.extend(operator_policy.extract_operator_candidates(
                raw_text,
                source_session_hash=digest(sha256.encode()),
                source_turn_ref=turn_id,
                observed_at=observed_at,
            ))
        extracted = payload_candidates(
            raw_text,
            source_session_hash=digest(sha256.encode()),
            source_turn_ref=turn_id,
            observed_at=observed_at,
        )
        for item in extracted:
            item["source_line"] = number
        session_payloads.extend(extracted)
    topic_counts = Counter(topic for item in visible for topic in item["topics"])
    user_security = sum(bool(item["topics"]) for item in visible if item["role"] == "user")
    all_security = sum(bool(item["topics"]) for item in visible)
    if not document or not messages:
        classification, reasons = "error", ["no-parseable-session-content"]
    elif user_security >= 2 or (user_security >= 1 and all_security >= 2):
        classification, reasons = "security", ["repeated-user-security-intent"]
    elif user_security == 1 or all_security >= 2:
        classification, reasons = "ambiguous", ["limited-or-assistant-only-security-signal"]
    else:
        classification, reasons = "non-security", ["no-material-security-intent"]
    session_id = document.get("session_id")
    return {
        "schema_version": SCHEMA_VERSION,
        "source_platform": platform,
        "source_id": stable_id("session-source", sha256),
        "sha256": sha256,
        "classification": classification,
        "classification_reasons": reasons,
        "session_ids": [str(session_id)] if session_id else [],
        "parent_thread_ids": [],
        "topics": dict(sorted(topic_counts.items())),
        "line_count": len(messages),
        "parse_errors": 0 if document else 1,
        "duplicate_events": 0,
        "event_types": {"message": len(messages)},
        "visible_turns": visible,
        "tool_summaries": [],
        "operator_candidates": operator_candidates,
        "payload_candidates": session_payloads,
        "redactions": redactions,
    }


def extract_candidates(session: dict[str, Any]) -> list[dict[str, Any]]:
    if session["classification"] not in {"security", "ambiguous"}:
        return []
    turns = session["visible_turns"]
    candidates = []
    session_key = (session.get("session_ids") or [session["source_id"]])[0]
    for index, turn in enumerate(turns):
        if turn["role"] != "user" or not turn.get("negative_signal"):
            continue
        if not turn.get("learning_security_signal"):
            continue
        if not turn["topics"] and not turn.get("concepts"):
            continue
        following = turns[index + 1 : index + 9]
        assistant = next((item for item in following if item["role"] == "assistant"), None)
        if assistant is None:
            continue
        later_user = next((item for item in following if item["role"] == "user"), None)
        tool_verified = any(
            item.get("kind") == "result"
            and item.get("verification_hint")
            and item.get("line", 0) > turn["line"]
            and item.get("line", 0) <= assistant["line"] + 500
            and (
                item.get("exit_code") == 0
                or item.get("returncode") == 0
                or str(item.get("status", "")).casefold() in {"passed", "completed", "ok"}
            )
            for item in session.get("tool_summaries", [])
        )
        concepts = sorted(set(turn.get("concepts", [])) | set(assistant.get("concepts", [])))
        suggested_skill = (
            "blue-evidence-validation"
            if "evidence" in concepts and not {"route-coverage", "api-discovery"} & set(concepts)
            else "blue-network-traffic-analysis"
            if "traffic-tool" in concepts and not {"route-coverage", "api-discovery"} & set(concepts)
            else "blue-web-patrol"
        )
        # Assistant self-assertion is never validation. Require an explicit later
        # user acceptance or a structured tool result with a verification signal.
        validated = bool(
            (later_user and later_user.get("acceptance_signal")) or tool_verified
        )
        target_specific = bool(turn["target_signal"] or assistant["target_signal"])
        candidate_type = (
            turn.get("candidate_type")
            if turn.get("candidate_type") != "workflow-rule"
            else assistant.get("candidate_type", "workflow-rule")
        )
        behavior_delta = {
            "failure_mode": candidate_type,
            "required_actions": [
                "reconstruct the relevant scope and evidence state",
                "validate the corrected behavior with tool evidence or explicit acceptance",
                "preserve unresolved prerequisites and continue the investigation",
            ],
            "evidence_gate": "structured tool evidence or explicit user acceptance",
            "stop_gate": "scope coverage and candidate adjudication are complete",
            "conclusion_guard": "do not promote potential impact or assistant wording to a confirmed finding",
        }
        routing_concepts = [
            concept
            for concept in concepts
            if concept in {
                "evidence", "route-coverage", "api-discovery", "traffic-tool",
                "authentication", "authorization", "prerequisite-chain", "completion-gate",
            }
        ]
        cluster_key = f"{candidate_type}:{suggested_skill}:{','.join(routing_concepts) or 'general'}"
        correction_excerpt = str(turn.get("learning_excerpt") or "")
        method_excerpt = "; ".join(behavior_delta["required_actions"])
        acceptance_excerpt = (
            str(later_user.get("learning_excerpt") or "")
            if later_user and later_user.get("acceptance_signal")
            else None
        )
        if target_specific:
            correction_excerpt = "[TARGET_SPECIFIC_CONTENT_WITHHELD]"
            if acceptance_excerpt is not None:
                acceptance_excerpt = "[TARGET_SPECIFIC_CONTENT_WITHHELD]"
        candidates.append(
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": stable_id("session-learning", [session_key, turn["id"]]),
                "cluster_id": stable_id("learning-cluster", cluster_key),
                "candidate_type": candidate_type,
                "suggested_skill": suggested_skill,
                "concepts": concepts,
                "problem_summary": correction_excerpt,
                "correction_summary": (
                    "Validated reusable method change"
                    if validated
                    else "Method change requires independent validation"
                ),
                "source_session_hash": digest(session_key.encode()),
                "source_turn_ref": turn["id"],
                "validation_state": "validated" if validated else "unverified",
                "validation_evidence": (
                    "sanitized-tool-result"
                    if tool_verified
                    else "visible-acceptance-or-verification"
                    if validated
                    else "none"
                ),
                "target_specific": target_specific,
                "disposition": "candidate",
                "object_kind": "instruction-rule"
                if candidate_type == "workflow-rule"
                else "eval-case",
                "lesson_bundle": {
                    "behavior_delta": behavior_delta,
                    "failure_context": correction_excerpt,
                    "user_correction": correction_excerpt,
                    "successful_method": method_excerpt,
                    "acceptance": acceptance_excerpt,
                    "applicability": concepts,
                    "non_applicability": [
                        "target-specific values",
                        "assistant self-assertion without independent evidence",
                    ],
                    "positive_eval": {
                        "input_condition": concepts,
                        "required_behavior": behavior_delta["required_actions"],
                        "required_evidence": "structured tool evidence or explicit user acceptance",
                    },
                    "negative_eval": {
                        "input_condition": "similar wording without the applicability conditions",
                        "required_behavior": "do not activate or generalize the rule",
                    },
                    "forbidden_conclusion": [
                        "assistant wording alone proves validation",
                        "a zero exit code alone proves the security conclusion",
                    ],
                },
            }
        )
    return candidates


def covered_pattern(candidate: dict[str, Any]) -> str | None:
    concepts = set(candidate.get("concepts", []))
    if "route-coverage" in concepts:
        return "blue-web-patrol:route-execution-closure"
    if {"file-parser", "safety"} <= concepts:
        return "file-lifecycle-control"
    if {"authorization", "evidence"} <= concepts:
        return "authorization-boundary-classification"
    if {"business-state", "session", "evidence"} <= concepts:
        return "pre-authentication-state-provenance"
    if {"api-discovery", "evidence"} <= concepts:
        return "blue-web-patrol:validated-api-evidence"
    return None


def run(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    if args.sessions:
        source = args.source if args.source != "all" else "codex"
        entry = platforms.get_platform(source)
        session_format = entry["sessions"].get("format") or "codex-jsonl"
        roots = [(source, session_format, args.sessions.expanduser().resolve())]
    else:
        names = platforms.platform_ids() if args.source == "all" else (args.source,)
        roots = list(platforms.iter_supported_session_roots(names))
    roots = [(platform, session_format, root) for platform, session_format, root in roots if root.is_dir()]
    if not roots:
        raise SystemExit("no supported session directory found")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("sd-%Y%m%dT%H%M%SZ")
    run_root = RUNS / run_id
    if args.resume and (run_root / "summary.json").exists():
        return run_root, load_json(run_root / "summary.json", {})
    for private_directory in (STORE, RUNS, run_root):
        private_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            private_directory.chmod(0o700)
    state = load_json(STATE, {"schema_version": 1, "sources": {}})
    state_current = state.get("distiller_version") == DISTILLER_VERSION
    ledgers = []
    turns = []
    candidates = []
    operator_candidates = []
    session_payloads = []
    classifications: Counter[str] = Counter()
    topics: Counter[str] = Counter()
    seen_session_ids: dict[str, str] = {}
    seen_source_hashes: dict[str, str] = {}
    seen_turn_events: set[str] = set()
    cross_file_duplicate_events = 0
    duplicate_session_sources = 0
    duplicate_content_sources = 0
    parent_links = 0
    sources = sorted(
        (platform, session_format, path)
        for platform, session_format, root in roots
        for path in (
            root.glob("session_*.json")
            if session_format == "hermes-json"
            else root.rglob("*.jsonl")
        )
    )
    platform_counts: Counter[str] = Counter()
    for platform, session_format, path in sources:
        try:
            stat = path.stat()
            identity = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "inode": getattr(stat, "st_ino", 0)}
            cache_key = digest(f"{platform}:{path}".encode())
            previous = state["sources"].get(cache_key)
            sha256 = previous.get("sha256") if previous and previous.get("identity") == identity else file_digest(path)
            if state_current and previous and previous.get("sha256") == sha256 and previous.get("result"):
                result = previous["result"]
                reused = True
            else:
                result = (
                    parse_hermes_session(path, sha256, platform)
                    if session_format == "hermes-json"
                    else parse_session(path, sha256, platform)
                )
                state["sources"][cache_key] = {
                    "identity": identity,
                    "sha256": sha256,
                    "last_seen_at": now(),
                    "result": result,
                }
                reused = False
        except OSError as error:
            result = {
                "schema_version": SCHEMA_VERSION,
                "source_platform": platform,
                "source_id": stable_id("session-source", str(path)),
                "sha256": None,
                "classification": "error",
                "classification_reasons": [f"{type(error).__name__}"],
                "session_ids": [],
                "parent_thread_ids": [],
                "topics": {},
                "line_count": 0,
                "parse_errors": 1,
                "duplicate_events": 0,
                "event_types": {},
                "visible_turns": [],
                "tool_summaries": [],
                "operator_candidates": [],
                "payload_candidates": [],
                "redactions": 0,
            }
            reused = False
        result.setdefault("source_platform", platform)
        withhold_target_context(result.get("visible_turns", []))
        classifications[result["classification"]] += 1
        platform_counts[result.get("source_platform", platform)] += 1
        topics.update(result.get("topics", {}))
        duplicate_of = next(
            (
                seen_session_ids[session_id]
                for session_id in result.get("session_ids", [])
                if session_id in seen_session_ids
            ),
            None,
        )
        if duplicate_of:
            duplicate_session_sources += 1
        duplicate_content_of = (
            seen_source_hashes.get(str(result.get("sha256")))
            if result.get("sha256")
            else None
        )
        if duplicate_content_of:
            duplicate_content_sources += 1
        elif result.get("sha256"):
            seen_source_hashes[str(result["sha256"])] = result["source_id"]
        for session_id in result.get("session_ids", []):
            seen_session_ids.setdefault(session_id, result["source_id"])
        parent_links += len(result.get("parent_thread_ids", []))
        ledgers.append(
            {
                key: value
                for key, value in result.items()
                if key not in {
                    "visible_turns",
                    "tool_summaries",
                    "operator_candidates",
                    "payload_candidates",
                }
            }
            | {
                "path_hash": digest(str(path).encode()),
                "reused": reused,
                "visible_turn_count": len(result.get("visible_turns", [])),
                "tool_summary_count": len(result.get("tool_summaries", [])),
                "duplicate_session_of": duplicate_of,
                "duplicate_content_of": duplicate_content_of,
            }
        )
        for turn in result.get("visible_turns", []):
            if turn.get("event_sha256") in seen_turn_events:
                cross_file_duplicate_events += 1
                continue
            seen_turn_events.add(str(turn.get("event_sha256")))
            turns.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "source_id": result["source_id"],
                    **{
                        key: value
                        for key, value in turn.items()
                        if key != "learning_excerpt"
                    },
                }
            )
        if not duplicate_content_of:
            session_learning = extract_candidates(result)
            candidates.extend(session_learning)
            verified_turns = {
                item["source_turn_ref"]
                for item in session_learning
                if item.get("validation_state") == "validated"
            }
            for item in result.get("operator_candidates", []):
                value = dict(item)
                if value.get("target_specific"):
                    value["summary"] = "[TARGET_SPECIFIC_CONTENT_WITHHELD]"
                if value.get("source_turn_ref") in verified_turns:
                    value["validation_state"] = "validated"
                operator_candidates.append(value)
            for item in (
                result.get("payload_candidates", [])
                if result.get("classification") in {"security", "ambiguous"}
                else []
            ):
                value = dict(item)
                line = int(value.get("source_line", 0))
                tool_verified = any(
                    tool.get("kind") == "result"
                    and tool.get("verification_hint")
                    and line <= int(tool.get("line", 0)) <= line + 500
                    and (
                        tool.get("exit_code") == 0
                        or tool.get("returncode") == 0
                        or str(tool.get("status", "")).casefold()
                        in {"passed", "completed", "ok"}
                    )
                    for tool in result.get("tool_summaries", [])
                )
                if tool_verified:
                    value["validation_state"] = "validated"
                session_payloads.append(value)
    clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        clusters[candidate["cluster_id"]].append(candidate)
    disposition_counts: Counter[str] = Counter()
    eligible = []
    eligible_local_eval = []
    for values in clusters.values():
        sessions = {item["source_session_hash"] for item in values}
        validated = sum(item["validation_state"] == "validated" for item in values)
        for item in values:
            covered_by = covered_pattern(item)
            if covered_by:
                item["covered_by"] = covered_by
            if item["target_specific"]:
                disposition = "target-specific"
            elif covered_by:
                disposition = "covered"
            elif not item["concepts"]:
                disposition = "insufficient-evidence"
            elif len(values) > 1 and len(sessions) < len(values):
                disposition = "duplicate"
            elif len(sessions) >= 2 and validated >= 2:
                disposition = "eligible-for-review"
            elif item["validation_state"] == "validated":
                disposition = "eligible-for-local-eval"
            elif item["validation_state"] != "validated":
                disposition = "insufficient-evidence"
            else:
                disposition = "candidate"
            item["disposition"] = disposition
            item["independent_sessions"] = len(sessions)
            item["validated_occurrences"] = validated
            disposition_counts[disposition] += 1
            if disposition == "eligible-for-review":
                eligible.append(item["candidate_id"])
            elif disposition == "eligible-for-local-eval":
                eligible_local_eval.append(item["candidate_id"])
    write_jsonl(run_root / "session-source-ledger.jsonl", ledgers)
    write_jsonl(run_root / "security-turn-ledger.jsonl", turns)
    write_jsonl(run_root / "learning-candidates.jsonl", candidates)
    write_jsonl(
        run_root / "lesson-bundles.jsonl",
        [
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": item["candidate_id"],
                "cluster_id": item["cluster_id"],
                "suggested_skill": item["suggested_skill"],
                "object_kind": item["object_kind"],
                "validation_state": item["validation_state"],
                "source_session_hash": item["source_session_hash"],
                "source_turn_ref": item["source_turn_ref"],
                "lesson_bundle": item["lesson_bundle"],
            }
            for item in candidates
        ],
    )
    write_jsonl(
        run_root / "review-cards.jsonl",
        [
            {
                "schema_version": 1,
                "candidate_id": item["candidate_id"],
                "cluster_id": item["cluster_id"],
                "approval_state": (
                    "reviewable"
                    if item["disposition"] in {"eligible-for-review", "eligible-for-local-eval"}
                    else "blocked"
                ),
                "disposition": item["disposition"],
                "block_reasons": [
                    reason
                    for condition, reason in (
                        (item["target_specific"], "contains-target-specific-material"),
                        (item["validation_state"] != "validated", "missing-independent-validation"),
                        (bool(item.get("covered_by")), "already-covered-by-base"),
                        (
                            "[TARGET_SPECIFIC_CONTENT_WITHHELD]"
                            in {
                                item["lesson_bundle"]["user_correction"],
                                item["lesson_bundle"]["successful_method"],
                            },
                            "review-content-withheld",
                        ),
                    )
                    if condition
                ],
                "object_kind": item["object_kind"],
                "target_skill": item["suggested_skill"],
                "candidate_type": item["candidate_type"],
                "problem_or_trigger": item["lesson_bundle"]["failure_context"],
                "user_correction": item["lesson_bundle"]["user_correction"],
                "improved_method": item["lesson_bundle"]["successful_method"],
                "applicability": item["lesson_bundle"]["applicability"],
                "non_applicability": item["lesson_bundle"]["non_applicability"],
                "validation": {
                    "state": item["validation_state"],
                    "basis": item["validation_evidence"],
                    "independent_sessions": item.get("independent_sessions", 0),
                    "validated_occurrences": item.get("validated_occurrences", 0),
                },
                "evals": {
                    "positive": item["lesson_bundle"]["positive_eval"],
                    "negative": item["lesson_bundle"]["negative_eval"],
                    "forbidden_conclusions": item["lesson_bundle"]["forbidden_conclusion"],
                },
                "provenance": {
                    "source_session_hash": item["source_session_hash"],
                    "source_turn_ref": item["source_turn_ref"],
                },
            }
            for item in candidates
        ],
    )
    policy_store, resolved_policies, policy_conflicts = operator_policy.resolve_policy_candidates(
        operator_candidates,
        operator_policy.policy_path(),
    )
    write_jsonl(run_root / "operator-policy-candidates.jsonl", resolved_policies)
    write_jsonl(run_root / "policy-conflicts.jsonl", policy_conflicts)
    atomic_json(run_root / "operator-policy.json", policy_store)

    payload_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in session_payloads:
        payload_groups[(item["family"], item["payload_sha256"])].append(item)
    distilled_payloads: list[dict[str, Any]] = []
    for values in payload_groups.values():
        values.sort(key=lambda item: (str(item.get("observed_at", "")), item["candidate_id"]))
        latest = dict(values[-1])
        sessions = {item["source_session_hash"] for item in values}
        validated = sum(item.get("validation_state") == "validated" for item in values)
        latest.update(
            {
                "occurrences": len(values),
                "independent_sessions": len(sessions),
                "validated_occurrences": validated,
                "state": (
                    "eligible-for-review"
                    if latest.get("payload_policy") == "safe-auto"
                    and len(sessions) >= 2
                    and validated >= 1
                    else "blocked"
                    if latest.get("payload_policy") == "blocked"
                    else "candidate"
                ),
                "source_refs": sorted({item["source_turn_ref"] for item in values})[:100],
            }
        )
        latest.pop("source_line", None)
        distilled_payloads.append(latest)
    write_jsonl(
        run_root / "session-payload-candidates.jsonl",
        sorted(distilled_payloads, key=lambda item: (item["family"], item["candidate_id"])),
    )
    promotion = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "policy": {
            "minimum_independent_sessions": 2,
            "minimum_validated_occurrences": 2,
            "requires_cross_domain_regression": True,
            "automatic_repository_edit": False,
        },
        "eligible_for_review": sorted(set(eligible)),
        "eligible_for_local_eval": sorted(set(eligible_local_eval)),
        "operator_policy": {
            "active": len(policy_store.get("active", [])),
            "review": policy_store.get("review_count", 0),
            "conflicts": len(policy_conflicts),
        },
        "payload_templates": {
            "eligible_for_review": sum(
                item.get("state") == "eligible-for-review"
                for item in distilled_payloads
            ),
            "candidates": sum(item.get("state") == "candidate" for item in distilled_payloads),
            "blocked": sum(item.get("state") == "blocked" for item in distilled_payloads),
        },
        "promoted": [],
    }
    atomic_json(run_root / "promotion-manifest.json", promotion)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "distiller_version": DISTILLER_VERSION,
        "run_id": run_id,
        "generated_at": now(),
        "source_files": len(ledgers),
        "source_platforms": dict(sorted(platform_counts.items())),
        "classifications": dict(sorted(classifications.items())),
        "topics": dict(sorted(topics.items())),
        "visible_turns": len(turns),
        "cross_file_duplicate_events": cross_file_duplicate_events,
        "duplicate_session_sources": duplicate_session_sources,
        "duplicate_content_sources": duplicate_content_sources,
        "parent_links": parent_links,
        "learning_candidates": len(candidates),
        "candidate_dispositions": dict(sorted(disposition_counts.items())),
        "eligible_for_review": len(set(eligible)),
        "eligible_for_local_eval": len(set(eligible_local_eval)),
        "operator_policy_candidates": len(resolved_policies),
        "active_operator_policies": len(policy_store.get("active", [])),
        "operator_policy_conflicts": len(policy_conflicts),
        "session_payload_candidates": len(distilled_payloads),
        "safe_payloads_eligible_for_review": sum(
            item.get("state") == "eligible-for-review"
            for item in distilled_payloads
        ),
        "state": "complete",
        "session_coverage": {
            platform_id: (
                "full-transcript"
                if platforms.get_platform(platform_id)["sessions"].get("status") == "supported"
                else "not-exposed"
            )
            for platform_id in platforms.platform_ids()
        },
    }
    atomic_json(run_root / "summary.json", summary)
    state["distiller_version"] = DISTILLER_VERSION
    atomic_json(STATE, state)
    acknowledge_distillation_queue(run_id)
    return run_root, summary


def command_run(args: argparse.Namespace) -> None:
    if not args.sessions and args.source != "all":
        entry = platforms.get_platform(args.source)
        if entry["sessions"].get("status") == "not-exposed":
            print(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "source": args.source,
                "status": "not-exposed",
                "reason": "the platform does not expose a verified durable transcript format",
            }, ensure_ascii=False, indent=2))
            return
    if not args.run_id:
        args.run_id = datetime.now(timezone.utc).strftime("sd-%Y%m%dT%H%M%S.%fZ")
    try:
        run_root, summary = run(args)
    except BaseException as error:
        run_root = RUNS / str(args.run_id)
        run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            run_root.chmod(0o700)
        state = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        atomic_json(
            run_root / "summary.json",
            {
                "schema_version": SCHEMA_VERSION,
                "distiller_version": DISTILLER_VERSION,
                "run_id": args.run_id,
                "generated_at": now(),
                "state": state,
                "failure_type": type(error).__name__,
            },
        )
        raise
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(run_root)


def summary_sort_key(path: Path, value: dict[str, Any]) -> tuple[float, int, str]:
    generated = value.get("generated_at")
    timestamp = 0.0
    if isinstance(generated, str):
        try:
            timestamp = datetime.fromisoformat(generated.replace("Z", "+00:00")).timestamp()
        except ValueError:
            timestamp = 0.0
    try:
        modified = path.stat().st_mtime_ns
    except OSError:
        modified = 0
    return timestamp, modified, str(value.get("run_id") or path.parent.name)


def load_run_summaries() -> list[tuple[Path, dict[str, Any]]]:
    result: list[tuple[Path, dict[str, Any]]] = []
    for path in RUNS.glob("*/summary.json"):
        try:
            value = load_json(path, {})
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        value = dict(value)
        value.setdefault("run_id", path.parent.name)
        if not value.get("generated_at") or not value.get("state"):
            value["state"] = "legacy-unverifiable"
            value["status_reason"] = "summary lacks generated_at or state"
        result.append((path, value))
    return result


def command_status(args: argparse.Namespace) -> None:
    if args.run_id:
        path = RUNS / args.run_id / "summary.json"
        if not path.exists():
            raise SystemExit("session distillation run not found")
        matches = [(item_path, value) for item_path, value in load_run_summaries() if item_path == path]
        if not matches:
            raise SystemExit("session distillation run is invalid")
        print(json.dumps(matches[0][1], ensure_ascii=False, indent=2) + "\n", end="")
        return
    summaries = load_run_summaries()
    if not summaries:
        raise SystemExit("session distillation run not found")
    complete = [item for item in summaries if item[1].get("state") == "complete"]
    selected_path, selected = max(complete or summaries, key=lambda item: summary_sort_key(*item))
    recent: dict[str, dict[str, Any]] = {}
    for state in ("complete", "failed", "interrupted", "legacy-unverifiable"):
        candidates = [item for item in summaries if item[1].get("state") == state]
        if not candidates:
            continue
        _, value = max(candidates, key=lambda item: summary_sort_key(*item))
        recent[state] = {
            key: value.get(key)
            for key in ("run_id", "generated_at", "state", "distiller_version", "failure_type")
            if value.get(key) is not None
        }
    output = dict(selected)
    output["recent_runs"] = recent
    output["selected_by"] = "latest-complete-generated-at"
    output["summary_path"] = str(selected_path)
    print(json.dumps(output, ensure_ascii=False, indent=2) + "\n", end="")


def selected_run_root(run_id: str | None) -> Path:
    if run_id:
        root = RUNS / run_id
        if not (root / "summary.json").is_file():
            raise SystemExit(f"session distillation run not found: {run_id}")
        return root
    summaries = [item for item in load_run_summaries() if item[1].get("state") == "complete"]
    if not summaries:
        raise SystemExit("completed session distillation run not found")
    path, _ = max(summaries, key=lambda item: summary_sort_key(*item))
    return path.parent


def command_review(args: argparse.Namespace) -> None:
    root = selected_run_root(args.run_id)
    path = root / "review-cards.jsonl"
    if not path.is_file():
        raise SystemExit("review cards are unavailable; rerun session distillation with the current version")
    cards = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            card = json.loads(line)
        except json.JSONDecodeError:
            continue
        if args.candidate and card.get("candidate_id") not in args.candidate:
            continue
        if not args.include_blocked and card.get("approval_state") != "reviewable":
            continue
        cards.append(card)
    output = {
        "schema_version": 1,
        "run_id": root.name,
        "reviewable": sum(item.get("approval_state") == "reviewable" for item in cards),
        "blocked_included": sum(item.get("approval_state") == "blocked" for item in cards),
        "cards": cards,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Distill supported local agent security sessions")
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--source", choices=("all", *platforms.platform_ids()), default="all")
    run_parser.add_argument("--sessions", type=Path)
    run_parser.add_argument("--run-id")
    run_parser.add_argument("--resume", action="store_true")
    run_parser.add_argument("--incremental", action="store_true", help="reuse unchanged source hashes and process new transcript content")
    run_parser.set_defaults(function=command_run)
    import_parser = commands.add_parser("import")
    import_parser.add_argument("--platform", dest="source", choices=platforms.platform_ids(), required=True)
    import_parser.add_argument("--sessions", required=True, type=Path)
    import_parser.add_argument("--run-id")
    import_parser.set_defaults(function=command_run, resume=False, incremental=True)
    status = commands.add_parser("status")
    status.add_argument("run_id", nargs="?")
    status.add_argument("--json", action="store_true")
    status.set_defaults(function=command_status)
    review = commands.add_parser("review", help="show privacy-safe learning approval cards")
    review.add_argument("run_id", nargs="?")
    review.add_argument("--candidate", action="append", default=[])
    review.add_argument("--include-blocked", action="store_true")
    review.add_argument("--json", action="store_true")
    review.set_defaults(function=command_review)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
