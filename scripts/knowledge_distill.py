#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from hub_config import configured_report_sources
from knowledge_session import SESSIONS, atomic_json, load_manifest
from report_formats import FormatError, extract_document, redact
from report_ingestion import active_report_entries, build_artifact, load_profile_config
from security_terms import canonicalize_term


ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
CACHE_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_CACHE",
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "blue-sec-hub",
    )
)
SANDBOX_ROOT = CACHE_ROOT / "distillation-sandbox"
STORE = DATA_ROOT / "knowledge-distillation"
RUNS = STORE / "runs"
ARTIFACTS = STORE / "artifacts"
SOURCE_STATE = STORE / "source-state.json"
AUDITS = STORE / "audits"
PATTERN_ROOT = ROOT / "skills" / "blue-vulnerability-patterns" / "references"
SCHEMA_VERSION = 2
DISTILLER_VERSION = "1.5.0"
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_RATIO = 1000
MAX_ARCHIVE_DEPTH = 2
MAX_OCR_PAGES = 20

DOCUMENT_SUFFIXES = {".docx", ".docm", ".pdf", ".xlsx", ".doc", ".xls"}
TEXT_SUFFIXES = {".csv", ".txt", ".md", ".html", ".htm", ".mhtml"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".tif", ".tiff"}
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar"}
PROHIBITED_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".vbs", ".js", ".jsp", ".bat",
    ".cmd", ".ps1", ".sh", ".class", ".jar", ".apk", ".ipa", ".msi",
}
REPORT_SIGNALS = re.compile(
    r"漏洞|渗透|复测|整改|问题清单|风险|安全测试|扫描报告|攻防|弱口令|"
    r"未授权|越权|注入|XSS|SSRF|CSRF|RCE|CVE-|vulnerability|penetration|"
    r"retest|finding|remediation|security assessment",
    re.IGNORECASE,
)
SCANNER_SIGNALS = re.compile(
    r"漏洞扫描|主机扫描|基线|漏扫|scanner|nessus|openvas|awvs|appscan",
    re.IGNORECASE,
)
GENERIC_FINDING_LABEL = re.compile(
    r"^(?:安全)?漏洞\s*(?:扫描|接口|版本|POC)?$|^有漏洞的\s*URL$|^相关漏洞$|"
    r"^漏洞(?:名称|详情|描述|概述|类型|级别|信息)$|"
    r"^View Source Code$|^发现方式（.*）$|^攻击内容$|^未发现漏洞$|"
    r"^统一资产发现与漏洞检测工具$|^高危漏洞$|^具体描述$|"
    r"^漏洞(?:危害|归属单位|等级)$|"
    r"网络安全漏洞扫描系统.*安全评估报告",
    re.IGNORECASE,
)
GENERIC_ADVICE = re.compile(r"确保|应当|应该|必须|建议|需要|不得|最少资源|最小权限")
FINDING_STATUS_SUFFIX = re.compile(
    r"\s*[（(\[]\s*(?:已)?(?:修复|整改|关闭|解决|复测通过)\s*[）)\]]\s*$",
    re.IGNORECASE,
)
SENSITIVE_PATTERN = re.compile(
    r"https?://|(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)|"
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}|"
    r"/(?:api|rest|admin|internal|service|svc|v\d+)(?:/[A-Za-z0-9_{}:.-]+)+",
    re.IGNORECASE,
)
ROOT_CAUSE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("identifier-provenance-chain", re.compile(r"opaque|url.?key|下载键|标识符.*(?:来源|可获得)|对象引用.*(?:来源|链)|附件.*(?:预览|下载)", re.I)),
    ("object-authorization-lifecycle", re.compile(r"横向越权|跨(?:用户|账号|账户|租户|企业|组织).*(?:读取|访问|修改|篡改|伪造|删除|下载|中断)|(?:读取|修改|篡改|伪造|删除|下载|中断).*(?:他人|其他用户|其他租户|其他企业|其他组织)|bola|idor", re.I)),
    ("authorization-boundary-classification", re.compile(r"匿名(?:读取|访问|下载).*(?:内部|全局|敏感|工单|审批|结算)|未授权(?:读取|访问|下载)|无需登录.*(?:读取|访问|下载)", re.I)),
    ("sensitive-data-exposure", re.compile(r"匿名(?:读取|访问|泄露).*(?:生产|监控|日志|指标|设备|视频|配置)|(?:敏感|内部).*(?:信息|数据|日志|配置).*(?:泄露|暴露)", re.I)),
    ("server-side-code-execution", re.compile(r"容器逃逸|container escape|宿主机.*(?:root|代码执行)|服务端.*(?:命令|代码)执行", re.I)),
    ("message-delivery-abuse-control", re.compile(r"短信.*(?:轰炸|滥用|限频)|验证码.*(?:轰炸|发送|滥用)|邮件.*轰炸|message delivery", re.I)),
    ("oauth-public-client-binding", re.compile(r"oauth|oidc|pkce|authorization code|client.?secret|redirect.?uri", re.I)),
    ("identity-state-response-differential", re.compile(r"账号枚举|用户枚举|注册状态.*差异|identity.*enumeration|account.*enumeration", re.I)),
    ("cross-protocol-authorization-parity", re.compile(r"websocket|sse|长连接|跨协议|发布者|订阅者|publisher|subscriber", re.I)),
    ("workload-identity-rbac-blast-radius", re.compile(r"service.?account|role.?binding|cluster.?role|rbac|跨命名空间|namespace.*权限|tokenrequest|nodes/proxy|(?:工作负载|节点|cni).*(?:凭据|token).*(?:集群|配置|跨租户).*权限", re.I)),
    ("credential-forwarding-confused-deputy", re.compile(r"代带凭据|转发.*凭据|bearer.*转发|代理.*凭据|scraper.*credential|confused deputy", re.I)),
    ("monitoring-control-plane-integrity", re.compile(r"监控.*(?:写入|管理|控制|关闭)|日志.*伪造|告警.*(?:写入|静默|管理)|(?:删除|篡改|伪造).*(?:监控|告警|日志|指标)|alert.*silence|control.?plane.*write", re.I)),
    ("controller-reconciliation-amplification", re.compile(r"控制器.*(?:调谐|重建|自动创建)|reconcil|状态写入.*(?:高权限|特权)|controller.*privileg", re.I)),
    ("stream-registration-preemption", re.compile(r"注册.*(?:抢占|替换|中断)|会话.*抢占|中断.*(?:通道|流)|耗尽.*(?:客户端|会话).*槽位|client.*slot|session.*preempt", re.I)),
    ("path-normalization-control-bypass", re.compile(r"路径.*(?:规范化|绕过)|伪静态|分号.*(?:路径|后缀)|;\.(?:js|css|html)|gateway.*normal", re.I)),
    ("workflow-precondition-bypass", re.compile(r"资格绕过|审批绕过|配额绕过|余额.*绕过|前置条件|资源.*(?:组合|绑定)|业务逻辑绕过", re.I)),
    ("function-level-authorization", re.compile(r"垂直越权|功能级越权|bfla|低权限.*(?:管理|审批|配置)", re.I)),
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalized_report_family(path: Path) -> str:
    stem = path.stem.casefold()
    stem = re.sub(r"(?:19|20)\d{6}", " ", stem)
    stem = re.sub(r"(?:19|20)\d{2}[-_.]\d{1,2}[-_.]\d{1,2}", " ", stem)
    stem = re.sub(
        r"(?:危害)?补强版|最终版|终版|修订版|更新版|复测版|副本|copy|"
        r"\(\d+\)|（\d+）|\bv\d+(?:\.\d+)*\b",
        " ",
        stem,
        flags=re.I,
    )
    stem = re.sub(r"渗透测试报告|信息系统安全排查报告|安全评估报告|漏洞报告", " ", stem)
    stem = re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", stem)
    if len(stem) < 3:
        stem = re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", path.parent.name.casefold())
    return stem or "generic-report"


def version_family_id(path: Path) -> str:
    return "version-family-" + hash_text(
        f"{path.parent.resolve()}:{normalized_report_family(path)}"
    )[:16]


def report_version_rank(path: Path) -> tuple[int, int, int, int, str]:
    name = path.stem.casefold()
    explicit = sum(
        marker in name
        for marker in ("补强版", "最终版", "终版", "修订版", "更新版")
    )
    dates = [int(value) for value in re.findall(r"(?:19|20)\d{6}", name)]
    versions = [
        tuple(int(part) for part in value.split("."))
        for value in re.findall(r"(?<![a-z])v(\d+(?:\.\d+)*)", name, re.I)
    ]
    numeric_version = sum(
        part * (1000 ** max(0, 3 - index))
        for index, part in enumerate(max(versions, default=(0,))[:4])
    )
    try:
        stat = path.stat()
        mtime = stat.st_mtime_ns
        size = stat.st_size
    except OSError:
        mtime = size = 0
    return explicit, max(dates, default=0), numeric_version, mtime, f"{size:020d}:{path.name}"


def root_cause_for_finding(finding: dict[str, Any]) -> str | None:
    material = " ".join(
        str(item)
        for item in (
            finding.get("title"),
            finding.get("weakness_class"),
            *finding.get("term_matches", []),
        )
        if item
    )
    return next(
        (pattern_id for pattern_id, pattern in ROOT_CAUSE_RULES if pattern.search(material)),
        None,
    )


def finding_cluster_key(finding: dict[str, Any]) -> str:
    root_cause = finding.get("root_cause_id") or root_cause_for_finding(finding)
    if root_cause:
        return str(root_cause)
    weakness = FINDING_STATUS_SUFFIX.sub(
        "",
        str(finding.get("weakness_class") or "unknown").strip(),
    )
    return canonicalize_term(weakness)


def generic_finding_title(value: str) -> bool:
    value = value.strip()
    return bool(
        GENERIC_FINDING_LABEL.search(value)
        or (len(value) >= 24 and GENERIC_ADVICE.search(value))
    )


def independent_system_count(findings: Iterable[dict[str, Any]]) -> int:
    return len(
        {
            item["system_key"]
            for item in findings
            if item.get("system_key")
            and item.get("system_identity_confidence") == "strong"
        }
    )


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
    path.chmod(0o600)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


class VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in {"script", "style", "noscript", "svg"}:
            self.hidden += 1
        elif tag.casefold() in {"p", "div", "br", "tr", "li", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style", "noscript", "svg"} and self.hidden:
            self.hidden -= 1
        elif tag.casefold() in {"p", "div", "tr", "li"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)

    def text(self) -> str:
        return "\n".join(
            line.strip()
            for line in "".join(self.parts).splitlines()
            if line.strip()
        )


def extracted_text(value: str, format_name: str) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    redactions = 0
    for number, line in enumerate(value.splitlines(), start=1):
        clean, count = redact(line)
        redactions += count
        if clean.strip():
            blocks.append(
                {
                    "id": f"line:{number:06d}",
                    "kind": "line",
                    "text": clean.strip(),
                }
            )
    return {
        "format": format_name,
        "blocks": blocks,
        "text": "\n".join(block["text"] for block in blocks),
        "metadata": {},
        "stats": {"blocks": len(blocks), "redactions": redactions},
    }


def ocr_image(path: Path) -> str:
    if not shutil.which("tesseract"):
        raise FormatError("tesseract is unavailable")
    result = subprocess.run(
        ["tesseract", str(path), "stdout", "-l", "chi_sim+eng"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    return result.stdout


def ocr_pdf(path: Path, temporary: Path) -> str:
    if not shutil.which("pdftoppm") or not shutil.which("tesseract"):
        raise FormatError("PDF OCR tools are unavailable")
    prefix = temporary / "page"
    subprocess.run(
        [
            "pdftoppm", "-f", "1", "-l", str(MAX_OCR_PAGES), "-r", "150",
            "-png", str(path), str(prefix),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
    )
    return "\n".join(ocr_image(item) for item in sorted(temporary.glob("page-*.png")))


def extract_source(
    path: Path,
    temporary: Path,
    ocr_allowed: bool,
) -> tuple[dict[str, Any], str]:
    suffix = path.suffix.casefold()
    if suffix in {".doc", ".xls"}:
        value = extract_document(path)
        if value is None:
            raise FormatError("legacy conversion output is unsupported")
        value["format"] = suffix.lstrip(".")
        return value, value.get("metadata", {}).get("conversion", "legacy-converted")
    if suffix in {".html", ".htm", ".mhtml"}:
        raw = path.read_text(encoding="utf-8", errors="replace")
        parser = VisibleTextParser()
        parser.feed(raw)
        return extracted_text(html.unescape(parser.text()), suffix.lstrip(".")), "html-visible-text"
    if suffix in {".csv", ".txt", ".md"}:
        return extracted_text(
            path.read_text(encoding="utf-8", errors="replace"),
            suffix.lstrip("."),
        ), "text"
    if suffix in IMAGE_SUFFIXES:
        if not ocr_allowed:
            return extracted_text("", suffix.lstrip(".")), "ocr-not-applicable"
        return extracted_text(ocr_image(path), suffix.lstrip(".")), "ocr-image"
    value = extract_document(path)
    if value is None:
        raise FormatError(f"unsupported report format: {suffix}")
    if (
        suffix == ".pdf"
        and ocr_allowed
        and len(value.get("text", "").strip()) < 200
    ):
        ocr = ocr_pdf(path, temporary)
        if ocr.strip():
            return extracted_text(ocr, "pdf-ocr"), "ocr-pdf"
    return value, "native"


def report_score(path: Path, text: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    path_hits = len(REPORT_SIGNALS.findall(str(path)))
    text_hits = len(REPORT_SIGNALS.findall(text[:2_000_000]))
    if path_hits:
        reasons.append("report-like-path")
    if text_hits:
        reasons.append("report-content-signals")
    structural = sum(
        marker in text
        for marker in (
            "漏洞名称", "漏洞描述", "风险等级", "修复建议", "复测结果",
            "问题描述", "整改情况", "CWE-", "CVSS", "请求包", "响应包",
        )
    )
    if structural:
        reasons.append("report-structure")
    score = min(path_hits, 2) + min(text_hits, 3) + structural
    return score, reasons


def safe_member_name(name: str) -> bool:
    pure = PurePosixPath(name.replace("\\", "/"))
    return bool(
        name
        and "\x00" not in name
        and not name.startswith("-")
        and not pure.is_absolute()
        and ".." not in pure.parts
        and not (pure.parts and pure.parts[0].endswith(":"))
    )


def zip_members(path: Path) -> list[zipfile.ZipInfo]:
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as error:
        raise FormatError("invalid ZIP archive") from error
    with archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise FormatError("archive member limit exceeded")
        expanded = sum(item.file_size for item in members)
        if expanded > MAX_ARCHIVE_BYTES:
            raise FormatError("archive expanded-size limit exceeded")
        for item in members:
            if not safe_member_name(item.filename):
                raise FormatError("archive path traversal")
            unix_mode = (item.external_attr >> 16) & 0xFFFF
            if unix_mode and (unix_mode & 0o170000) not in {
                0,
                0o100000,
                0o040000,
            }:
                raise FormatError("archive contains a link or special file")
            if item.flag_bits & 0x1:
                raise FormatError("encrypted archive")
            if item.compress_size and item.file_size / item.compress_size > MAX_ARCHIVE_RATIO:
                raise FormatError("archive compression-ratio limit exceeded")
        return members


def extract_zip_members(path: Path, temporary: Path) -> list[Path]:
    members = zip_members(path)
    output: list[Path] = []
    with zipfile.ZipFile(path) as archive:
        for number, item in enumerate(members):
            if item.is_dir() or item.file_size > MAX_FILE_BYTES:
                continue
            suffix = Path(item.filename).suffix.casefold()
            if suffix not in DOCUMENT_SUFFIXES | TEXT_SUFFIXES | IMAGE_SUFFIXES | ARCHIVE_SUFFIXES:
                continue
            if suffix in IMAGE_SUFFIXES and not REPORT_SIGNALS.search(item.filename):
                continue
            destination = temporary / f"member-{number:06d}{suffix}"
            with archive.open(item) as source, destination.open("wb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            destination.chmod(0o600)
            output.append(destination)
    return output


def seven_zip_members(path: Path, temporary: Path) -> list[Path]:
    binary = shutil.which("7z")
    if not binary:
        raise FormatError("7z is unavailable")
    listing_result = subprocess.run(
        [binary, "l", "-slt", "-bd", "-p-", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    listing = listing_result.stdout + "\n" + listing_result.stderr
    if listing_result.returncode:
        if "password" in listing.casefold() or "encrypted" in listing.casefold():
            raise FormatError("encrypted archive")
        raise FormatError("invalid 7z/RAR archive")
    if "Encrypted = +" in listing:
        raise FormatError("encrypted archive")
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in listing.splitlines():
        if not line.strip() and current:
            records.append(current)
            current = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            current[key] = value
    if current:
        records.append(current)
    file_records = [item for item in records if item.get("Folder") == "-"]
    if len(file_records) > MAX_ARCHIVE_MEMBERS:
        raise FormatError("archive member limit exceeded")
    expanded = sum(int(item.get("Size", "0") or 0) for item in file_records)
    if expanded > MAX_ARCHIVE_BYTES:
        raise FormatError("archive expanded-size limit exceeded")
    output: list[Path] = []
    for number, item in enumerate(file_records):
        name = item.get("Path", "")
        if not safe_member_name(name):
            raise FormatError("archive path traversal")
        attributes = item.get("Attributes", "").casefold()
        if "symbolic" in attributes or attributes.startswith("l"):
            raise FormatError("archive contains a link or special file")
        size = int(item.get("Size", "0") or 0)
        packed = int(item.get("Packed Size", "0") or 0)
        if size > MAX_FILE_BYTES or (packed and size / packed > MAX_ARCHIVE_RATIO):
            continue
        suffix = Path(name).suffix.casefold()
        if suffix not in DOCUMENT_SUFFIXES | TEXT_SUFFIXES | IMAGE_SUFFIXES | ARCHIVE_SUFFIXES:
            continue
        if suffix in IMAGE_SUFFIXES and not REPORT_SIGNALS.search(name):
            continue
        result = subprocess.run(
            [binary, "x", "-so", "-bd", "-p-", str(path), name],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        if result.returncode:
            message = result.stderr.decode("utf-8", errors="replace")
            if "password" in message.casefold() or "encrypted" in message.casefold():
                raise FormatError("encrypted archive")
            raise FormatError("cannot read 7z/RAR member")
        if len(result.stdout) > MAX_FILE_BYTES:
            continue
        destination = temporary / f"member-{number:06d}{suffix}"
        destination.write_bytes(result.stdout)
        destination.chmod(0o600)
        output.append(destination)
    return output


def archive_members(path: Path, temporary: Path) -> list[Path]:
    if path.suffix.casefold() == ".zip":
        return extract_zip_members(path, temporary)
    return seven_zip_members(path, temporary)


def load_patterns() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(PATTERN_ROOT.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        for pattern in value.get("patterns", []):
            result[str(pattern["id"])] = pattern
    return result


def pattern_for_finding(finding: dict[str, Any], patterns: dict[str, dict[str, Any]]) -> str | None:
    root_cause = root_cause_for_finding(finding)
    if root_cause in patterns:
        return root_cause
    material = " ".join(
        str(item)
        for item in (
            finding.get("title"),
            finding.get("weakness_class"),
            *finding.get("term_matches", []),
        )
        if item
    ).casefold()
    for pattern_id, pattern in patterns.items():
        terms = [pattern_id, *pattern.get("aliases", []), *pattern.get("cwes", [])]
        if any(str(term).casefold() in material for term in terms):
            return pattern_id
    canonical = canonicalize_term(str(finding.get("weakness_class") or ""))
    for pattern_id, pattern in patterns.items():
        if canonical in pattern.get("canonical_terms", []):
            return pattern_id
    return None


def artifact_findings(
    source: Path,
    source_sha256: str,
    extracted: dict[str, Any],
    scanner_only: bool,
) -> list[dict[str, Any]]:
    artifact = build_artifact(
        source,
        source_sha256,
        extracted,
        load_profile_config(),
        hash_text(f"distill:{source_sha256}"),
    )
    system_id = str(artifact["document"].get("system_id") or "")
    system_identity_confidence = (
        "strong"
        if system_id and not system_id.startswith("unknown-")
        else "weak"
    )
    stable_system = (
        normalized_report_family(source)
        if system_identity_confidence == "weak"
        else system_id
    )
    system_key = hash_text(stable_system)[:16]
    result: list[dict[str, Any]] = []
    for finding in artifact.get("findings", []):
        result.append(
            {
                "finding_id": finding["candidate_id"],
                "title": finding["title"],
                "weakness_class": finding["weakness_class"],
                "term_matches": finding.get("term_matches", []),
                "confidence": finding.get("confidence", "medium"),
                "status": finding.get("status", "reported"),
                "evidence_state": "historical",
                "system_key": system_key,
                "system_identity_confidence": system_identity_confidence,
                "source_sha256": source_sha256,
                "scanner_only": scanner_only,
                "root_cause_id": root_cause_for_finding(finding),
                "evidence_refs": finding.get("evidence_refs", []),
            }
        )
    return result


def relevant_image(path: Path) -> bool:
    if REPORT_SIGNALS.search(path.name):
        return True
    try:
        siblings = list(path.parent.iterdir())[:500]
    except OSError:
        return False
    image_count = sum(
        item.is_file() and item.suffix.casefold() in IMAGE_SUFFIXES
        for item in siblings
    )
    has_report = any(
        item.is_file()
        and item.suffix.casefold() in DOCUMENT_SUFFIXES | TEXT_SUFFIXES
        and REPORT_SIGNALS.search(item.name)
        for item in siblings
    )
    return bool(
        image_count <= 50
        and has_report
        and REPORT_SIGNALS.search(str(path.parent))
    )


def source_candidates(roots: list[tuple[Path, str, str]]) -> Iterable[tuple[Path, str, str]]:
    seen: set[Path] = set()
    for root, mode, alias in roots:
        if root.is_file() or root.is_symlink():
            candidates = [root]
        elif root.is_dir():
            candidates = (
                item
                for item in root.rglob("*")
                if item.is_file()
                and not any(part.startswith(".") for part in item.relative_to(root).parts)
            )
        else:
            continue
        for path in candidates:
            absolute = path.absolute()
            if absolute in seen:
                continue
            seen.add(absolute)
            yield absolute, mode, alias


def source_identity(path: Path) -> tuple[str, dict[str, int]]:
    info = path.lstat()
    identity = {
        "mtime_ns": info.st_mtime_ns,
        "size": info.st_size,
        "inode": getattr(info, "st_ino", 0),
    }
    return hash_text(str(path)), identity


def artifact_cache(root: Path, source_sha256: str) -> Path:
    version = DISTILLER_VERSION.replace(".", "-")
    return (
        root
        / "artifacts"
        / source_sha256[:2]
        / f"{source_sha256}-{version}.json"
    )


def process_report(
    path: Path,
    source_sha256: str,
    cache_root: Path,
    scanner_only: bool,
    ocr_allowed: bool | None = None,
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    target = artifact_cache(cache_root, source_sha256)
    if target.exists():
        cached = json.loads(target.read_text(encoding="utf-8"))
        cached_findings = cached.get("findings", [])
        cache_is_current = (
            cached.get("distiller_version") == DISTILLER_VERSION
            and all(
                finding.get("system_key")
                and finding.get("system_identity_confidence") in {"strong", "weak"}
                for finding in cached_findings
            )
        )
        if cache_is_current:
            state = "not-report" if cached.get("classification") == "not-report" else "current"
            return state, cached_findings, cached.get("diagnostics", {})
    legacy_target = cache_root / "artifacts" / source_sha256[:2] / f"{source_sha256}.json"
    if legacy_target.exists():
        cached = json.loads(legacy_target.read_text(encoding="utf-8"))
        cached_findings = cached.get("findings", [])
        if all(
            finding.get("system_key")
            and finding.get("system_identity_confidence") in {"strong", "weak"}
            for finding in cached_findings
        ):
            cached["distiller_version"] = DISTILLER_VERSION
            cached.setdefault("diagnostics", {})["migrated_conservatively"] = True
            atomic_json(target, cached)
            return "current", cached_findings, cached.get("diagnostics", {})
    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    SANDBOX_ROOT.chmod(0o700)
    with tempfile.TemporaryDirectory(
        prefix="blue-sec-distill-",
        dir=SANDBOX_ROOT,
    ) as temporary_name:
        temporary = Path(temporary_name)
        temporary.chmod(0o700)
        if ocr_allowed is None:
            ocr_allowed = bool(REPORT_SIGNALS.search(str(path))) or (
                path.suffix.casefold() in IMAGE_SUFFIXES and relevant_image(path)
            )
        extracted, method = extract_source(path, temporary, ocr_allowed)
        score, reasons = report_score(path, extracted.get("text", ""))
        if score < 2:
            diagnostics = {
                "score": score,
                "reasons": reasons,
                "method": method,
                "finding_count": 0,
            }
            atomic_json(
                target,
                {
                    "schema_version": SCHEMA_VERSION,
                    "distiller_version": DISTILLER_VERSION,
                    "source_sha256": source_sha256,
                    "created_at": now(),
                    "classification": "not-report",
                    "findings": [],
                    "diagnostics": diagnostics,
                },
            )
            return "not-report", [], diagnostics
        findings = artifact_findings(path, source_sha256, extracted, scanner_only)
        value = {
            "schema_version": SCHEMA_VERSION,
            "distiller_version": DISTILLER_VERSION,
            "source_sha256": source_sha256,
            "created_at": now(),
            "findings": findings,
            "diagnostics": {
                "score": score,
                "reasons": reasons,
                "method": method,
                "finding_count": len(findings),
            },
        }
        atomic_json(target, value)
        return "extracted", findings, value["diagnostics"]


def process_archive(
    path: Path,
    source_sha256: str,
    cache_root: Path,
    scanner_only: bool,
    depth: int = 0,
    ocr_allowed: bool | None = None,
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    if depth >= MAX_ARCHIVE_DEPTH:
        return "unsafe-archive", [], {"reason": "nested-depth-limit"}
    all_findings: list[dict[str, Any]] = []
    archive_ocr_allowed = bool(ocr_allowed) or bool(
        REPORT_SIGNALS.search(str(path))
    )
    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    SANDBOX_ROOT.chmod(0o700)
    with tempfile.TemporaryDirectory(
        prefix="blue-sec-archive-",
        dir=SANDBOX_ROOT,
    ) as temporary_name:
        temporary = Path(temporary_name)
        temporary.chmod(0o700)
        members = archive_members(path, temporary)
        states: Counter[str] = Counter()
        for member in members:
            member_sha = sha256_file(member)
            try:
                if member.suffix.casefold() in ARCHIVE_SUFFIXES:
                    state, findings, _ = process_archive(
                        member,
                        member_sha,
                        cache_root,
                        scanner_only,
                        depth + 1,
                        archive_ocr_allowed,
                    )
                else:
                    state, findings, _ = process_report(
                        member,
                        member_sha,
                        cache_root,
                        scanner_only,
                        archive_ocr_allowed,
                    )
            except (FormatError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                state, findings = "error", []
            states[state] += 1
            all_findings.extend(findings)
    return "extracted", all_findings, {
        "member_count": sum(states.values()),
        "member_states": dict(states),
        "finding_count": len(all_findings),
    }


def sanitize_candidate(value: str) -> str:
    value = SENSITIVE_PATTERN.sub("<target-specific>", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:200]


def failure_reason_counts(path: Path) -> dict[str, int]:
    counts: Counter[str] = Counter()
    if not path.exists():
        return {}
    mappings = (
        ("encrypted", "encrypted-content"),
        ("file-size-limit", "file-size-limit"),
        ("nested-depth-limit", "archive-depth-limit"),
        ("path traversal", "archive-path-traversal"),
        ("too many", "archive-member-limit"),
        ("expands beyond", "archive-expansion-limit"),
        ("compression ratio", "archive-ratio-limit"),
        ("invalid zip", "invalid-archive"),
        ("invalid 7z", "invalid-archive"),
        ("invalid rar", "invalid-archive"),
        ("invalid office archive", "invalid-office-container"),
        ("xml part is too large", "office-part-size-limit"),
        ("extractor-timeout", "extractor-timeout"),
        ("extractor-exit", "extractor-error"),
        ("isolation is unavailable", "isolation-unavailable"),
    )
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        status = str(record.get("status") or "")
        if status not in {"encrypted", "error", "oversized", "unsafe-archive"}:
            continue
        reason = str(record.get("reason") or status).casefold()
        category = next(
            (label for marker, label in mappings if marker in reason),
            f"{status}-other",
        )
        counts[category] += 1
    return dict(sorted(counts.items()))


def run_distillation(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    roots: list[tuple[Path, str, str]] = []
    configured_roots: list[tuple[Path, str, str]] = []
    direct_roots: list[tuple[Path, str, str]] = []
    if args.configured or (not args.paths and not args.session):
        for number, (path, mode) in enumerate(configured_report_sources(existing_only=True)):
            item = (path, mode, f"configured-{number + 1}")
            roots.append(item)
            configured_roots.append(item)
    for number, path in enumerate(args.paths):
        item = (path.expanduser().resolve(), "security-reports", f"explicit-{number + 1}")
        roots.append(item)
        direct_roots.append(item)

    session = None
    session_root = None
    cache_root = STORE
    if args.session:
        session = load_manifest(args.session)
        session_root = SESSIONS / args.session
        item = (Path(session["source_path"]), "security-reports", "session")
        roots.append(item)
        direct_roots.append(item)
        cache_root = session_root / "knowledge-distillation"
    if not roots:
        raise SystemExit("no knowledge roots are configured or supplied")

    sources = list(source_candidates(direct_roots))
    if configured_roots:
        for entry in active_report_entries(include_ambiguous=args.include_ambiguous):
            path = Path(str(entry.get("source", "")))
            for root, mode, alias in configured_roots:
                try:
                    matches = path == root or path.is_relative_to(root)
                except (OSError, ValueError):
                    matches = False
                if matches:
                    sources.append((path, mode, alias))
                    break
    sources = list(dict.fromkeys(sources))
    version_groups: dict[str, list[Path]] = defaultdict(list)
    for path, _, _ in sources:
        if path.suffix.casefold() in DOCUMENT_SUFFIXES | TEXT_SUFFIXES:
            version_groups[version_family_id(path)].append(path)
    canonical_versions = {
        family: max(paths, key=report_version_rank)
        for family, paths in version_groups.items()
    }

    run_id = args.run_id or datetime.now(timezone.utc).strftime("kd-%Y%m%dT%H%M%SZ")
    run_root = (session_root / "distillation" if session_root else RUNS) / run_id
    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_root.chmod(0o700)
    if args.resume and (run_root / "summary.json").exists():
        return run_root, json.loads(
            (run_root / "summary.json").read_text(encoding="utf-8")
        )
    source_ledger = run_root / "source-ledger.jsonl"
    raw_findings = run_root / ".raw-findings.jsonl"
    finding_ledger = run_root / "finding-ledger.jsonl"
    pattern_candidates = run_root / "pattern-candidates.jsonl"
    promotion_manifest = run_root / "promotion-manifest.json"
    for output in (source_ledger, raw_findings, finding_ledger, pattern_candidates):
        if output.exists() and not args.resume:
            output.unlink()

    state_path = cache_root / "source-state.json"
    state = load_json(state_path, {"schema_version": 1, "sources": {}})
    patterns = load_patterns()
    counts: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    if args.resume and raw_findings.exists():
        for line in raw_findings.read_text(encoding="utf-8").splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    seen_hashes: dict[str, str] = {}
    processed_ids: set[str] = set()
    if args.resume and source_ledger.exists():
        for line in source_ledger.read_text(encoding="utf-8").splitlines():
            try:
                previous_record = json.loads(line)
                processed_ids.add(previous_record["source_id"])
                counts[str(previous_record.get("status"))] += 1
            except (KeyError, json.JSONDecodeError):
                continue

    for path, mode, alias in sources:
        source_id, identity = source_identity(path)
        if source_id in processed_ids:
            continue
        suffix = path.suffix.casefold()
        family_id = (
            version_family_id(path)
            if suffix in DOCUMENT_SUFFIXES | TEXT_SUFFIXES
            else None
        )
        record: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "source_id": source_id,
            "root_alias": alias,
            "path": str(path),
            "suffix": suffix,
            "observed_at": now(),
            "status": None,
            "reason": None,
            "version_family_id": family_id,
            "canonical_version": bool(
                family_id and canonical_versions.get(family_id) == path
            ),
        }
        record_findings: list[dict[str, Any]] = []
        try:
            if path.is_symlink():
                record.update(status="unsupported", reason="symbolic-link")
            elif identity["size"] > MAX_FILE_BYTES and suffix not in ARCHIVE_SUFFIXES:
                record.update(status="oversized", reason="file-size-limit")
            elif suffix in PROHIBITED_SUFFIXES:
                record.update(status="unsupported", reason="executable-or-active-content")
            elif any(
                marker in part.casefold()
                for part in path.parts
                for marker in (".exe.extracted", ".dll.extracted", ".jar.extracted")
            ):
                record.update(status="unsupported", reason="active-content-extraction")
            elif suffix in IMAGE_SUFFIXES and not relevant_image(path):
                record.update(status="not-report", reason="image-without-report-context")
            elif suffix not in DOCUMENT_SUFFIXES | TEXT_SUFFIXES | IMAGE_SUFFIXES | ARCHIVE_SUFFIXES:
                record.update(status="unsupported", reason="unsupported-format")
            elif mode == "documents" and suffix not in {".docx", ".docm", ".pdf", ".xlsx"}:
                record.update(status="unsupported", reason="source-mode-documents")
            elif suffix in TEXT_SUFFIXES and not REPORT_SIGNALS.search(str(path)):
                record.update(status="not-report", reason="text-without-report-path-signal")
            elif suffix in ARCHIVE_SUFFIXES and path.with_suffix("").is_dir():
                record.update(
                    status="deduplicated",
                    reason="matching-extracted-directory",
                )
            else:
                previous = state["sources"].get(source_id)
                source_sha256 = None
                if previous and previous.get("identity") == identity:
                    source_sha256 = previous.get("sha256")
                source_sha256 = source_sha256 or sha256_file(path)
                record["sha256"] = source_sha256
                state["sources"][source_id] = {
                    "identity": identity,
                    "sha256": source_sha256,
                    "last_seen_at": now(),
                }
                if source_sha256 in seen_hashes:
                    record.update(
                        status="deduplicated",
                        reason=f"same-content-as:{seen_hashes[source_sha256]}",
                    )
                else:
                    seen_hashes[source_sha256] = source_id
                    scanner_only = bool(SCANNER_SIGNALS.search(str(path)))
                    if suffix in ARCHIVE_SUFFIXES:
                        status, extracted_findings, diagnostics = process_archive(
                            path, source_sha256, cache_root, scanner_only
                        )
                    else:
                        status, extracted_findings, diagnostics = process_report(
                            path, source_sha256, cache_root, scanner_only
                        )
                    record.update(status=status, diagnostics=diagnostics)
                    for finding in extracted_findings:
                        finding["source_family_id"] = family_id or source_sha256
                        finding["canonical_source_version"] = bool(
                            family_id and canonical_versions.get(family_id) == path
                        )
                    record_findings.extend(extracted_findings)
        except subprocess.TimeoutExpired:
            record.update(status="error", reason="extractor-timeout")
        except subprocess.CalledProcessError as error:
            record.update(status="error", reason=f"extractor-exit:{error.returncode}")
        except FormatError as error:
            message = str(error)
            if "encrypted" in message:
                status = "encrypted"
            elif suffix in ARCHIVE_SUFFIXES and (
                "archive" in message or "path traversal" in message
            ):
                status = "unsafe-archive"
            else:
                status = "error"
            record.update(status=status, reason=message)
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            record.update(status="error", reason=f"{type(error).__name__}:{error}")
        counts[str(record["status"])] += 1
        for finding in record_findings:
            append_jsonl(raw_findings, finding)
        findings.extend(record_findings)
        append_jsonl(source_ledger, record)

    atomic_json(state_path, state)
    cluster: dict[str, list[dict[str, Any]]] = defaultdict(list)
    finding_counts: Counter[str] = Counter()
    canonical_version_fingerprints = {
        (
            str(item.get("source_family_id") or item.get("source_sha256")),
            finding_cluster_key(item),
            canonicalize_term(str(item.get("title") or "unknown")),
        )
        for item in findings
        if item.get("canonical_source_version")
    }
    seen_version_fingerprints: set[tuple[str, str, str]] = set()
    for finding in findings:
        pattern_id = pattern_for_finding(finding, patterns)
        root_cause = finding.get("root_cause_id") or root_cause_for_finding(finding)
        version_fingerprint = (
            str(finding.get("source_family_id") or finding.get("source_sha256")),
            finding_cluster_key(finding),
            canonicalize_term(str(finding.get("title") or "unknown")),
        )
        duplicate_version = bool(
            not finding.get("canonical_source_version")
            and (
                version_fingerprint in canonical_version_fingerprints
                or version_fingerprint in seen_version_fingerprints
            )
        )
        if duplicate_version:
            disposition = "duplicate-version"
            key = str(root_cause or "duplicate-version")
        elif generic_finding_title(str(finding.get("title") or "")):
            disposition = "rejected"
            key = "generic-report-label"
        elif finding.get("scanner_only"):
            disposition = "scanner-only"
            key = canonicalize_term(str(finding.get("weakness_class") or "unknown"))
        elif pattern_id:
            disposition = "covered-by-pattern"
            key = pattern_id
        elif finding.get("confidence") not in {"high", "medium"}:
            disposition = "insufficient-evidence"
            key = "insufficient-evidence"
        elif SENSITIVE_PATTERN.search(str(finding.get("title") or "")):
            disposition = "target-specific"
            key = canonicalize_term(str(finding.get("weakness_class") or "unknown"))
        else:
            disposition = "new-pattern-candidate"
            key = finding_cluster_key(finding)
        value = dict(finding)
        value["disposition"] = disposition
        value["pattern_id"] = pattern_id
        value["root_cause_id"] = root_cause
        append_jsonl(finding_ledger, value)
        finding_counts[disposition] += 1
        seen_version_fingerprints.add(version_fingerprint)
        if disposition in {"new-pattern-candidate", "scanner-only"}:
            cluster[key].append(value)

    eligible = 0
    eligible_reviews: list[dict[str, Any]] = []
    for key, values in sorted(cluster.items()):
        if key in patterns:
            continue
        source_count = len(
            {
                item.get("source_family_id") or item["source_sha256"]
                for item in values
            }
        )
        system_count = independent_system_count(values)
        non_scanner = sum(not item.get("scanner_only") for item in values)
        candidate = {
            "schema_version": SCHEMA_VERSION,
            "candidate_id": f"pattern-{hash_text(key)[:16]}",
            "canonical_term": sanitize_candidate(key),
            "sample_title": sanitize_candidate(str(values[0].get("title") or key)),
            "occurrences": len(values),
            "independent_sources": source_count,
            "independent_systems": system_count,
            "non_scanner_occurrences": non_scanner,
            "state": (
                "eligible-for-review"
                if source_count >= 2 and system_count >= 2 and non_scanner >= 1
                else "candidate"
            ),
            "evidence_state": "historical",
            "contains_raw_report_text": False,
        }
        eligible += candidate["state"] == "eligible-for-review"
        if candidate["state"] == "eligible-for-review":
            eligible_reviews.append(
                {
                    "candidate_id": candidate["candidate_id"],
                    "canonical_term": candidate["canonical_term"],
                    "occurrences": candidate["occurrences"],
                    "independent_sources": candidate["independent_sources"],
                    "independent_systems": candidate["independent_systems"],
                }
            )
        append_jsonl(pattern_candidates, candidate)

    promotion = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": now(),
        "policy": {
            "minimum_independent_sources": 2,
            "minimum_independent_systems": 2,
            "scanner_only_can_promote": False,
            "requires_cross_domain_regression": True,
            "automatic_repository_edit": False,
        },
        "eligible_for_review": eligible,
        "promoted": [],
        "reason": "Internal evidence creates candidates; repository changes require generic fixtures and review.",
    }
    atomic_json(promotion_manifest, promotion)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": now(),
        "roots": [alias for _, _, alias in roots],
        "source_counts": dict(sorted(counts.items())),
        "finding_counts": dict(sorted(finding_counts.items())),
        "failure_reason_counts": failure_reason_counts(source_ledger),
        "findings": len(findings),
        "patterns_loaded": len(patterns),
        "eligible_pattern_candidates": eligible,
        "eligible_candidate_reviews": eligible_reviews,
        "version_lineage": {
            "families": len(version_groups),
            "files": sum(len(paths) for paths in version_groups.values()),
            "noncanonical_versions": sum(
                max(0, len(paths) - 1) for paths in version_groups.values()
            ),
        },
        "state": "complete",
        "workspace": str(run_root),
        "temporary_session": args.session,
    }
    atomic_json(run_root / "summary.json", summary)
    raw_findings.unlink(missing_ok=True)
    AUDITS.mkdir(parents=True, exist_ok=True, mode=0o700)
    AUDITS.chmod(0o700)
    public_summary = dict(summary)
    public_summary.pop("workspace", None)
    atomic_json(AUDITS / f"{run_id}.json", public_summary)
    if session is not None:
        session["touched_at"] = now()
        session["touched_epoch"] = time.time()
        session.setdefault("distillation_runs", []).append(run_id)
        atomic_json(SESSIONS / args.session / "session.json", session)
    return run_root, summary


def command_run(args: argparse.Namespace) -> None:
    run_root, summary = run_distillation(args)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(run_root)


def command_status(args: argparse.Namespace) -> None:
    candidates = list(RUNS.glob(f"{args.run_id}/summary.json"))
    candidates.extend(SESSIONS.glob(f"*/distillation/{args.run_id}/summary.json"))
    if len(candidates) != 1:
        raise SystemExit(f"distillation run not found or ambiguous: {args.run_id}")
    print(candidates[0].read_text(encoding="utf-8"), end="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Distill local historical vulnerability reports into generic pattern candidates"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("paths", nargs="*", type=Path)
    run.add_argument("--configured", action="store_true")
    run.add_argument("--session")
    run.add_argument("--run-id")
    run.add_argument("--resume", action="store_true")
    run.add_argument(
        "--include-ambiguous",
        action="store_true",
        help="include ambiguous report artifacts in an explicit review run",
    )
    run.set_defaults(function=command_run)

    status = commands.add_parser("status")
    status.add_argument("run_id")
    status.set_defaults(function=command_status)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
