#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        str(Path.home() / ".local" / "share" / "blue-sec-hub"),
    )
)
DISTILL_ROOT = DATA_ROOT / "knowledge-distillation"
CATALOG = DISTILL_ROOT / "local-hypothesis-catalog.json"

# The mapping is deliberately generic. It only routes a historical title to a
# test family; it never turns historical text into a current finding.
FAMILY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("authorization.object-level", re.compile(r"越权|未授权|idor|bola|对象.*授权", re.I)),
    ("authorization.function-level", re.compile(r"功能.*越权|权限绕过|bfla|强制访问|后台.*未授权", re.I)),
    ("authorization.property-level", re.compile(r"批量赋值|属性.*越权|字段.*篡改|mass assignment", re.I)),
    ("authorization.tenant-parent-state", re.compile(r"租户|组织.*越权|父级.*绑定|tenant", re.I)),
    ("authorization.workflow-state", re.compile(r"状态.*绕过|审批.*绕过|流程.*绕过|前置条件", re.I)),
    ("authorization.identifier-provenance", re.compile(r"identifier-provenance|标识符来源|opaque.*来源|对象引用.*链", re.I)),
    ("authorization.cross-protocol-parity", re.compile(r"cross-protocol|跨协议|websocket.*(?:未授权|越权)|流式.*权限", re.I)),
    ("identity-session.authentication", re.compile(r"认证绕过|登录绕过|弱口令|任意.*登录", re.I)),
    ("identity-session.session-token", re.compile(r"会话|session|jwt|token|cookie", re.I)),
    ("identity-session.oauth-sso", re.compile(r"oauth|oidc|sso|单点登录", re.I)),
    ("identity-session.message-delivery", re.compile(r"message-delivery|短信.*(?:轰炸|滥用)|验证码.*发送", re.I)),
    ("identity-session.response-differential", re.compile(r"identity-state|账号枚举|用户枚举|注册状态.*差异", re.I)),
    ("injection.sql-nosql-orm", re.compile(r"sql.*注入|nosql|orm.*注入", re.I)),
    ("injection.xml-ldap-xpath", re.compile(r"xxe|xml.*实体|ldap.*注入|xpath.*注入", re.I)),
    ("browser-content.xss-dom-richtext", re.compile(r"xss|跨站脚本|dom.*注入", re.I)),
    ("files-data-export.path-read-download", re.compile(r"任意文件.*(?:读|下载)|目录穿越|路径穿越", re.I)),
    ("files-data-export.upload-validation", re.compile(r"文件上传|任意文件上传|上传绕过", re.I)),
    ("server-side-processing.ssrf-url-fetch", re.compile(r"ssrf|服务端请求伪造", re.I)),
    ("business-logic.lifecycle-integrity", re.compile(r"逻辑漏洞|业务绕过|资格绕过|配额绕过|重复领取", re.I)),
    ("platform-exposure.client-bootstrap-config", re.compile(r"敏感信息泄露|配置泄露|密钥泄露|源码泄露", re.I)),
    ("platform-exposure.debug-admin-docs", re.compile(r"swagger|api文档|调试接口|管理后台暴露", re.I)),
    ("infrastructure.workload-identity-rbac", re.compile(r"workload-identity|service.?account|role.?binding|rbac", re.I)),
    ("infrastructure.credential-forwarding", re.compile(r"credential-forwarding|代带凭据|代理.*凭据|confused deputy", re.I)),
    ("infrastructure.control-plane-integrity", re.compile(r"monitoring-control-plane|监控.*写入|告警.*静默|日志.*伪造", re.I)),
    ("infrastructure.reconciliation-amplification", re.compile(r"controller-reconciliation|控制器.*调谐|状态写入.*高权限", re.I)),
    ("api-protocol.stream-registration", re.compile(r"stream-registration|会话.*抢占|注册.*中断|client.*slot", re.I)),
)
REJECT_TEXT = re.compile(
    r"\blicen[cs]e\b|covered code|source code form|executable means|copyright|"
    r"隐私政策|服务条款|免责声明|招聘|采购公告",
    re.I,
)


def now() -> str:
    return datetime.now(UTC).isoformat()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def newest_run_files(filename: str, root: Path = DISTILL_ROOT) -> list[Path]:
    """Use the newest persistent run and newest temporary-session run."""
    selected: dict[str, Path] = {}
    for path in (root / "runs").glob(f"*/{filename}"):
        summary_path = path.parent / "summary.json"
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        category = "temporary" if summary.get("temporary_session") else "persistent"
        if category not in selected or path.stat().st_mtime > selected[category].stat().st_mtime:
            selected[category] = path
    return [selected[key] for key in ("persistent", "temporary") if key in selected]


def candidate_sources(root: Path = DISTILL_ROOT) -> list[Path]:
    return newest_run_files("pattern-candidates.jsonl", root)


def finding_sources(root: Path = DISTILL_ROOT) -> list[Path]:
    return newest_run_files("finding-ledger.jsonl", root)


def latest_candidates(root: Path = DISTILL_ROOT) -> Path | None:
    sources = candidate_sources(root)
    return max(sources, key=lambda item: item.stat().st_mtime) if sources else None


def formal_patterns() -> list[dict[str, Any]]:
    result = []
    reference_root = ROOT / "skills" / "blue-vulnerability-patterns" / "references"
    for path in sorted(reference_root.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for pattern in value.get("patterns", []):
            result.append({"id": pattern.get("id"), "domain": value.get("domain")})
    return result


def map_family(title: str) -> str | None:
    for family, pattern in FAMILY_RULES:
        if pattern.search(title):
            return family
    return None


def build_catalog(
    source: Path | None = None,
    destination: Path = CATALOG,
    extra_run_roots: list[Path] | None = None,
) -> dict[str, Any]:
    extra_run_roots = extra_run_roots or []
    sources = [source] if source else candidate_sources()
    sources.extend(
        path
        for root in extra_run_roots
        if (path := root / "pattern-candidates.jsonl").is_file()
    )
    formal = formal_patterns()
    entries: list[dict[str, Any]] = []
    dispositions = {"local-hypothesis": 0, "unmapped": 0, "rejected": 0}
    seen = set()
    for source_item in sources:
        if not source_item or not source_item.exists():
            continue
        for line in source_item.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            title = str(item.get("canonical_term") or item.get("sample_title") or "").strip()
            candidate_id = str(item.get("candidate_id") or "hyp-" + hashlib.sha256(title.encode()).hexdigest()[:16])
            if candidate_id in seen:
                continue
            seen.add(candidate_id)
            if not title or REJECT_TEXT.search(title):
                dispositions["rejected"] += 1
                continue
            family = map_family(title)
            if not family:
                dispositions["unmapped"] += 1
                continue
            dispositions["local-hypothesis"] += 1
            entries.append(
                {
                    "id": candidate_id,
                    "family": family,
                    "state": "local-hypothesis",
                    "independent_sources": int(item.get("independent_sources", 0)),
                    "independent_systems": int(item.get("independent_systems", 0)),
                    "evidence_state": "historical",
                }
            )
    # Finding ledgers provide complete accountability. Pattern clusters above
    # provide corroboration, but a single cluster may represent many reports.
    finding_entries: list[dict[str, Any]] = []
    finding_dispositions = {
        "local-hypothesis": 0,
        "unmapped-local-hypothesis": 0,
        "target-history": 0,
        "covered-by-formal-pattern": 0,
        "scanner-only": 0,
        "duplicate-version": 0,
        "rejected": 0,
    }
    seen_findings = set()
    finding_ledgers = [] if source is not None else finding_sources()
    finding_ledgers.extend(
        path
        for root in extra_run_roots
        if (path := root / "finding-ledger.jsonl").is_file()
    )
    for ledger in finding_ledgers:
        for line in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding_id = str(item.get("finding_id") or "")
            finding_key = "|".join(
                (
                    str(item.get("source_sha256") or ""),
                    finding_id,
                    hashlib.sha256(str(item.get("title") or "").encode()).hexdigest()[:12],
                )
            )
            if not finding_id:
                continue
            if finding_key in seen_findings:
                finding_dispositions["duplicate-version"] += 1
                continue
            seen_findings.add(finding_key)
            disposition = str(item.get("disposition") or "")
            if disposition == "covered-by-pattern":
                finding_dispositions["covered-by-formal-pattern"] += 1
                continue
            if disposition == "scanner-only":
                finding_dispositions["scanner-only"] += 1
                continue
            if disposition == "duplicate-version":
                finding_dispositions["duplicate-version"] += 1
                continue
            if disposition == "target-specific":
                finding_dispositions["target-history"] += 1
                continue
            if disposition != "new-pattern-candidate":
                finding_dispositions["rejected"] += 1
                continue
            title = " ".join(
                str(item.get(key) or "")
                for key in ("weakness_class", "title")
            )
            family = map_family(title)
            state = "local-hypothesis" if family else "unmapped-local-hypothesis"
            finding_dispositions[state] += 1
            finding_entries.append(
                {
                    "id": "finding-hyp-" + hashlib.sha256(finding_key.encode()).hexdigest()[:16],
                    "family": family,
                    "state": state,
                    "evidence_state": "historical",
                    "confirmation_policy": "current-response-required",
                }
            )
    effective_entries = finding_entries if finding_ledgers else entries
    effective_dispositions = finding_dispositions if finding_ledgers else dispositions
    value = {
        "schema_version": 1,
        "generated_at": now(),
        "source": {
            "ledger_sha256": hashlib.sha256(
                "".join(
                    hashlib.sha256(item.read_bytes()).hexdigest()
                    for item in [*sources, *finding_ledgers]
                    if item and item.exists()
                ).encode()
            ).hexdigest() if sources else None,
            "ledgers": [str(item.parent.name) for item in sources if item],
            "candidate_count": sum(dispositions.values()),
            "finding_candidate_count": (
                finding_dispositions["local-hypothesis"]
                + finding_dispositions["unmapped-local-hypothesis"]
            ),
        },
        "formal_patterns": formal,
        "local_hypotheses": sorted(
            effective_entries,
            key=lambda item: (str(item.get("family") or ""), item["id"]),
        ),
        "pattern_cluster_hypotheses": sorted(entries, key=lambda item: (item["family"], item["id"])),
        "dispositions": effective_dispositions,
        "pattern_cluster_dispositions": dispositions,
        "source_finding_ledgers": [str(item.parent.name) for item in finding_ledgers],
        "finding_policy": "priority-and-applicability-seed-only; current response evidence required",
    }
    atomic_json(destination, value)
    return value


def load_catalog(refresh: bool = False) -> dict[str, Any]:
    sources = [*candidate_sources(), *finding_sources()]
    stale = not CATALOG.exists() or (
        bool(sources) and max(item.stat().st_mtime for item in sources) > CATALOG.stat().st_mtime
    )
    if refresh or stale:
        return build_catalog()
    try:
        return json.loads(CATALOG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return build_catalog()


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the local, non-confirming Web hypothesis catalog")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--source", type=Path)
    build.add_argument("--run-root", type=Path, action="append", default=[])
    sub.add_parser("status")
    args = parser.parse_args()
    value = (
        build_catalog(args.source, extra_run_roots=args.run_root)
        if args.command == "build"
        else load_catalog()
    )
    print(json.dumps(value, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
