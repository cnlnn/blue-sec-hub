#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "learning_policy.json"
DEFAULT_CONDITIONS = "Applies to equivalent tasks and evidence."
TARGET_PATTERNS = {
    "URL": re.compile(r"https?://[^\s`'\"]+", re.IGNORECASE),
    "domain": re.compile(
        r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}"
        r"(?![A-Za-z0-9-])"
    ),
    "IP address": re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
    "absolute API path": re.compile(
        r"(?<![A-Za-z0-9_.-])/(?:api|rest|graphql|admin|internal|service|svc|v\d+)"
        r"(?:/[A-Za-z0-9_{}:.-]+)+",
        re.IGNORECASE,
    ),
    "UUID": re.compile(
        r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-"
        r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}(?![A-Fa-f0-9])"
    ),
    "opaque identifier": re.compile(
        r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{20,}(?![A-Fa-f0-9])"
    ),
    "person or account": re.compile(
        r"(?:姓名|账号|用户|负责人|参与人)\s*[:：=]\s*[\u3400-\u9fff]{2,4}"
        r"|[赵钱孙李周吴郑王冯陈蒋沈韩杨朱秦许何吕张孔曹严华金魏陶姜谢邹苏潘葛范彭鲁韦马苗方袁柳史唐薛雷贺倪汤罗毕郝安常于傅齐康伍余顾孟黄萧尹姚邵汪毛米戴宋熊纪董梁杜阮蓝席季贾江郭梅林钟徐高夏蔡田樊胡霍万卢莫房陆翁段温庄阎廖刘叶黎乔谭曾][\u3400-\u9fff]{1,2}(?=的(?:账号|用户|权限|查询)|本人|自己|可见|或匿名|与匿名)",
        re.IGNORECASE,
    ),
    "object identifier": re.compile(
        r"(?:对象|用户|账号|订单|任务|工单|租户).{0,8}(?:ID|Id|id|编号)"
        r"\s*[:：=]\s*[A-Za-z0-9_-]{3,}",
        re.IGNORECASE,
    ),
    "task field": re.compile(
        r"(?<![A-Za-z0-9_])(?:participantUserRightId|participantId|woNo|urlKey)"
        r"(?![A-Za-z0-9_])",
        re.IGNORECASE,
    ),
}
EXECUTION_PLAN_RE = re.compile(
    r"(?:^|\n)\s*(?:#{1,6}\s+|(?:PR|阶段|Phase)\s*\d+\b|\d+[.、]\s+)",
    re.IGNORECASE,
)
PROMOTED_TEXT_FIELDS = (
    "task",
    "failure",
    "correction",
    "successful_pattern",
    "conditions",
)
NON_DOMAIN_SUFFIXES = {
    "css",
    "csv",
    "doc",
    "docx",
    "html",
    "js",
    "json",
    "jsonl",
    "md",
    "pdf",
    "py",
    "txt",
    "vue",
    "xls",
    "xlsx",
    "yaml",
    "yml",
}


def load_policy() -> dict[str, Any]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def validate_policy(policy: dict[str, Any] | None = None) -> list[str]:
    policy = policy or load_policy()
    failures: list[str] = []
    if policy.get("schema_version") != 1:
        failures.append("learning policy schema_version must be 1")
    if not isinstance(policy.get("policy_version"), int):
        failures.append("learning policy needs an integer policy_version")
    scope = policy.get("scope")
    if not isinstance(scope, dict):
        failures.append("learning policy scope must be an object")
    else:
        for key in ("local_skill_updates", "upstream_supplements"):
            if scope.get(key) != "all":
                failures.append(f"learning policy scope.{key} must be all")
    requirements = policy.get("requirements")
    if not isinstance(requirements, dict):
        failures.append("learning policy requirements must be an object")
    else:
        for key in (
            "target_independent",
            "explicit_applicability",
            "validation_evidence",
            "preserve_upstream",
        ):
            if requirements.get(key) is not True:
                failures.append(f"learning policy requirements.{key} must be true")
    generalization = policy.get("generalization")
    if not isinstance(generalization, dict):
        failures.append("learning policy generalization must be an object")
    elif generalization.get("unit") != "declared-skill-scope":
        failures.append(
            "learning policy generalization.unit must be declared-skill-scope"
        )
    return failures


def target_specific_findings(text: str) -> list[str]:
    findings = []
    for label, pattern in TARGET_PATTERNS.items():
        for match in pattern.finditer(text):
            if (
                label == "domain"
                and match.group(0).rsplit(".", 1)[-1].casefold()
                in NON_DOMAIN_SUFFIXES
            ):
                continue
            findings.append(f"{label}: {match.group(0)!r}")
            break
    if len(EXECUTION_PLAN_RE.findall(text)) >= 3:
        findings.append("full execution plan")
    return findings


def promotion_failures(
    record: dict[str, Any],
    extra_promoted_text: list[str] | None = None,
) -> list[str]:
    failures = validate_policy()
    conditions = str(record.get("conditions", "")).strip()
    if not conditions or conditions == DEFAULT_CONDITIONS:
        failures.append("promotion needs explicit applicability and exclusion conditions")
    evidence = [
        str(item).strip()
        for item in record.get("evidence_refs", [])
        if str(item).strip()
    ]
    if not evidence:
        failures.append("promotion needs validation evidence")
    promoted_text = "\n".join(
        str(record.get(field, "")) for field in PROMOTED_TEXT_FIELDS
    )
    promoted_text += "\n" + "\n".join(extra_promoted_text or [])
    findings = target_specific_findings(promoted_text)
    if findings:
        failures.append(
            "promoted material contains deployment-specific identifiers: "
            + ", ".join(findings)
        )
    return failures


def promotion_attestation(record: dict[str, Any]) -> dict[str, Any]:
    policy = load_policy()
    return {
        "policy_version": policy["policy_version"],
        "scope": "all-local-skills-and-upstream-supplements",
        "generalization_unit": policy["generalization"]["unit"],
        "target_specific_scan": "passed",
        "conditions": record["conditions"],
        "evidence_refs": record.get("evidence_refs", []),
    }


if __name__ == "__main__":
    failures = validate_policy()
    if failures:
        raise SystemExit("\n".join(failures))
    policy = load_policy()
    print(
        json.dumps(
            {
                "schema_version": policy["schema_version"],
                "policy_version": policy["policy_version"],
                "scope": policy["scope"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
