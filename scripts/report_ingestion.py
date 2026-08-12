#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit
from xml.etree.ElementTree import ParseError

from hub_config import configured_report_sources
from report_formats import EXTRACTOR_VERSION, FormatError, extract_document
from security_terms import expand_query


ROOT = Path(__file__).resolve().parents[1]
PROFILE_CONFIG = ROOT / "report_profiles.json"
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
STORE = DATA_ROOT / "report-ingestion"
ARTIFACTS = STORE / "artifacts"
LOCAL_PROFILES = STORE / "profiles"
INDEX = STORE / "index.jsonl"
DECISIONS = STORE / "decisions.jsonl"
SCAN_RUNS = STORE / "scan-runs"
SCAN_STATE = STORE / "scan-state.json"
CONTRACT_SCHEMA_VERSION = 2
RELEVANCE_VERSION = 1
MAX_FILE_BYTES = 100 * 1024 * 1024
SUPPORTED_SUFFIXES = {
    ".csv",
    ".docx",
    ".docm",
    ".doc",
    ".har",
    ".http",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".pdf",
    ".html",
    ".htm",
    ".mhtml",
    ".txt",
    ".xlsx",
    ".xls",
    ".xml",
    ".yaml",
    ".yml",
}
DOCUMENT_SUFFIXES = {".docx", ".docm", ".pdf", ".xlsx"}
SECURITY_REPORT_SUFFIXES = {
    ".docx", ".docm", ".doc", ".pdf", ".xlsx", ".xls",
    ".csv", ".txt", ".md", ".html", ".htm", ".mhtml",
}
URL = re.compile(r"https?://[^\s<>\"|\u3400-\u9fff]+", re.IGNORECASE)
REQUEST_LINE = re.compile(
    r"(?im)\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+"
    r"(https?://[^\s]+|/[^\s]+)"
)
DATE = re.compile(r"(?<!\d)(20\d{2})[-年/.]?([01]\d)[-月/.]?([0-3]\d)")
SEVERITY = re.compile(
    r"^\s*(?:[\[【(（]\s*(严重|高危|高|中危|中|低危|低)\s*"
    r"[\]】)）]|(严重|高危|高|中危|中|低危|低)\s*[:：])\s*(.+)$"
)
NUMBERED_HEADING = re.compile(
    r"^\s*\d+(?:\.\d+)*(?:\.\s+|、\s*)(.{2,100})$"
)
INTERESTING_TITLE = re.compile(
    r"漏洞|注入|越权|未授权|泄露|绕过|劫持|执行|弱口令|"
    r"枚举|盲注|请求走私|配置错误|硬编码|短信轰炸|任意|"
    r"RCE|XSS|SSRF|CSRF|JWT|SQLi|IDOR|BOLA",
    re.IGNORECASE,
)
EXCLUDED_TITLES = {
    "漏洞",
    "漏洞详情",
    "漏洞概述",
    "漏洞类型",
    "漏洞综述",
    "安全测试结果详情",
    "安全问题归纳",
    "修复建议",
    "问题描述",
    "URL",
    "URL（可罗列）",
}
STATUS_MAP = (
    ("部分修复", "partially-fixed"),
    ("未修复", "reported"),
    ("已修复", "fixed"),
    ("修复完成", "fixed"),
    ("无法复现", "not-reproduced"),
    ("未复现", "not-reproduced"),
)
FINDING_SECTION_SIGNAL = re.compile(
    r"漏洞|安全问题|风险(?:详情|描述|清单)|finding|vulnerability",
    re.IGNORECASE,
)
EVIDENCE_CONTROL_SIGNAL = re.compile(
    r"证据|请求|响应|影响|修复|整改|复现|攻击路径|HTTP/\d(?:\.\d)?|"
    r"evidence|request|response|impact|remediation|reproduction",
    re.IGNORECASE,
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def hash_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False) + "\n")
    path.chmod(0o600)


def write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(
        "".join(json.dumps(value, ensure_ascii=False) + "\n" for value in values),
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def load_profile_config() -> dict[str, Any]:
    value = json.loads(PROFILE_CONFIG.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1:
        raise ValueError("report_profiles.json has an unsupported schema")
    profiles = value.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("report_profiles.json must contain profiles")

    combined = {
        "schema_version": value["schema_version"],
        "profile_set_version": value.get("profile_set_version", 1),
        "labels": dict(value.get("labels", {})),
        "profiles": [dict(profile) for profile in profiles],
    }
    if LOCAL_PROFILES.exists():
        for path in sorted(LOCAL_PROFILES.glob("*.json")):
            overlay = json.loads(path.read_text(encoding="utf-8"))
            if overlay.get("schema_version") != 1:
                raise ValueError(f"invalid local report profile: {path}")
            for key, labels in overlay.get("labels", {}).items():
                combined["labels"].setdefault(key, [])
                combined["labels"][key].extend(labels)
            combined["profiles"].extend(overlay.get("profiles", []))

    identifiers: set[tuple[str, int]] = set()
    for profile in combined["profiles"]:
        identifier = profile.get("id")
        version = profile.get("version")
        signals = profile.get("signals")
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[a-z0-9-]+", identifier)
            or not isinstance(version, int)
            or version < 1
            or not isinstance(signals, list)
            or not all(isinstance(item, str) and item for item in signals)
        ):
            raise ValueError(f"invalid report profile: {profile}")
        key = (identifier, version)
        if key in identifiers:
            raise ValueError(f"duplicate report profile: {identifier}@{version}")
        identifiers.add(key)
    combined["digest"] = hash_json(combined)
    return combined


def recognize_profile(text: str, config: dict[str, Any]) -> dict[str, Any]:
    ranked: list[tuple[int, dict[str, Any], list[str]]] = []
    for profile in config["profiles"]:
        matched = [signal for signal in profile["signals"] if signal in text]
        ranked.append((len(matched), profile, matched))
    score, profile, matched = max(
        ranked,
        key=lambda item: (item[0], item[1]["version"], item[1]["id"]),
    )
    minimum = int(profile.get("minimum_signals", 1))
    if score < minimum:
        return {
            "profile_id": "generic-security-report",
            "profile_version": 1,
            "confidence": "low",
            "matched_signals": matched,
        }
    confidence = "high" if score >= max(3, minimum + 1) else "medium"
    return {
        "profile_id": profile["id"],
        "profile_version": profile["version"],
        "confidence": confidence,
        "matched_signals": matched,
    }


def classify_relevance(
    recognition: dict[str, Any],
    text: str,
) -> dict[str, Any]:
    profile = str(recognition.get("profile_id") or "")
    confidence = str(recognition.get("confidence") or "low")
    if profile != "generic-security-report" and confidence in {"high", "medium"}:
        return {
            "version": RELEVANCE_VERSION,
            "disposition": "accepted",
            "reasons": ["recognized-security-report"],
        }
    finding_signal = bool(FINDING_SECTION_SIGNAL.search(text))
    evidence_signal = bool(EVIDENCE_CONTROL_SIGNAL.search(text))
    if finding_signal and evidence_signal:
        return {
            "version": RELEVANCE_VERSION,
            "disposition": "ambiguous",
            "reasons": ["generic-with-finding-signal", "generic-with-evidence-signal"],
        }
    reasons = []
    if not finding_signal:
        reasons.append("missing-finding-signal")
    if not evidence_signal:
        reasons.append("missing-evidence-or-control-signal")
    return {
        "version": RELEVANCE_VERSION,
        "disposition": "non-security",
        "reasons": reasons,
    }


def block_cells(block: dict[str, Any]) -> list[str]:
    cells = block.get("cells")
    if isinstance(cells, list):
        return [str(value).strip() for value in cells if str(value).strip()]
    return [str(block.get("text", "")).strip()]


def label_values(
    blocks: list[dict[str, Any]], labels: list[str]
) -> list[tuple[str, str]]:
    normalized_labels = {label.casefold(): label for label in labels}
    result: list[tuple[str, str]] = []
    for index, block in enumerate(blocks):
        cells = block_cells(block)
        for position, cell in enumerate(cells):
            normalized = cell.rstrip(":：").strip().casefold()
            if normalized in normalized_labels and position + 1 < len(cells):
                result.append((cells[position + 1], block["id"]))
                continue
            for label in labels:
                match = re.match(
                    rf"^\s*{re.escape(label)}\s*[:：]\s*(.+)$",
                    cell,
                    re.IGNORECASE,
                )
                if match:
                    result.append((match.group(1).strip(), block["id"]))
        text = str(block.get("text", "")).rstrip(":：").strip()
        if (
            text.casefold() in normalized_labels
            and index + 1 < len(blocks)
        ):
            result.append((str(blocks[index + 1]["text"]).strip(), block["id"]))
    return list(dict.fromkeys(result))


def clean_url(value: str) -> str | None:
    value = value.rstrip(".,;，。；）)]}'\"")
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
        return None
    try:
        port_number = parts.port
    except ValueError:
        return None
    port = f":{port_number}" if port_number else ""
    host = parts.hostname.casefold()
    netloc = f"{host}{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.casefold(), netloc, path, "", ""))


def collect_urls(text: str) -> list[str]:
    result = []
    for match in URL.finditer(text):
        value = clean_url(match.group(0))
        if value:
            result.append(value)
    return list(dict.fromkeys(result))


def collect_entrypoints(text: str) -> list[str]:
    result: list[str] = []
    method_paths: set[str] = set()
    for method, target in REQUEST_LINE.findall(text):
        if target.casefold().startswith(("http://", "https://")):
            cleaned = clean_url(target)
            if not cleaned:
                continue
            path = urlsplit(cleaned).path or "/"
        else:
            path = target.split("?", 1)[0].rstrip(".,;")
        result.append(f"{method.upper()} {path}")
        method_paths.add(path)
    for value in collect_urls(text):
        path = urlsplit(value).path or "/"
        if path != "/" and path not in method_paths:
            result.append(f"HTTP {path}")
    return list(dict.fromkeys(result))


def normalize_system_id(system_name: str | None, urls: list[str], sha256: str) -> str:
    if urls:
        host = urlsplit(urls[0]).hostname
        if host:
            return host.casefold()
    if system_name:
        value = re.sub(
            r"[^\w.-]+",
            "-",
            system_name.casefold(),
            flags=re.UNICODE,
        ).strip("-")
        if value:
            return value[:100]
    return f"report-{sha256[:16]}"


def infer_title(path: Path, blocks: list[dict[str, Any]], metadata: dict[str, Any]) -> str:
    if metadata.get("title"):
        return str(metadata["title"]).strip()
    for block in blocks[:20]:
        text = str(block.get("text", "")).strip()
        if 4 <= len(text) <= 160 and text not in {"目录", "目 录"}:
            return text
    return path.stem


def infer_date(path: Path, blocks: list[dict[str, Any]], config: dict[str, Any]) -> str | None:
    values = label_values(blocks, config["labels"].get("report_date", []))
    candidates = [value for value, _ in values]
    candidates.extend([path.stem, *[part for part in path.parts[-3:]]])
    for value in candidates:
        match = DATE.search(value)
        if match:
            return "-".join(match.groups())
    return None


def infer_status(path: Path, text: str) -> tuple[str, str | None]:
    material = f"{path}\n{text}"
    for marker, status in STATUS_MAP:
        if marker in material:
            return status, marker
    return "reported", None


def infer_status_from_segment(text: str) -> tuple[str | None, str | None]:
    for marker, status in STATUS_MAP:
        if marker in text:
            return status, marker
    return None, None


def severity_and_title(value: str) -> tuple[str | None, str]:
    match = SEVERITY.match(value)
    if not match:
        return None, value.strip()
    label = match.group(1) or match.group(2)
    severity = {
        "严重": "critical",
        "高危": "high",
        "高": "high",
        "中危": "medium",
        "中": "medium",
        "低危": "low",
        "低": "low",
    }[label]
    return severity, match.group(3).strip()


def weakness_for(title: str) -> tuple[str, list[str]]:
    expansion = expand_query(title)
    canonical = [str(value) for value in expansion["canonical"]]
    return (canonical[-1] if canonical else title.strip(), canonical)


def finding_title_key(title: str) -> str:
    value = re.sub(r"^\s*\d+\s+", "", title)
    value = re.sub(
        r"^\s*[（(【\[]\s*(?:已修复|未修复|部分修复)\s*[）)】\]]\s*",
        "",
        value,
    )
    return re.sub(r"[\W_]+", "", value.casefold(), flags=re.UNICODE)


def finding_title_candidates(
    path: Path,
    blocks: list[dict[str, Any]],
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    raw: list[tuple[int, str, str, str | None, bool]] = []
    weakness_labels = config["labels"].get("weakness", [])
    for value, anchor in label_values(blocks, weakness_labels):
        index = next(
            (number for number, block in enumerate(blocks) if block["id"] == anchor),
            0,
        )
        severity, title = severity_and_title(value)
        raw.append((index, title, anchor, severity, True))

    for index, block in enumerate(blocks):
        values = block_cells(block)
        for value in values:
            heading = NUMBERED_HEADING.match(value)
            candidate = heading.group(1).strip() if heading else value.strip()
            severity, candidate = severity_and_title(candidate)
            if severity and INTERESTING_TITLE.search(candidate):
                raw.append((index, candidate, block["id"], severity, True))
            elif heading and INTERESTING_TITLE.search(candidate):
                raw.append((index, candidate, block["id"], None, True))
            elif (
                index == 0
                and len(candidate) <= 120
                and INTERESTING_TITLE.search(candidate)
            ):
                raw.append((index, candidate, block["id"], None, False))

        text = str(block.get("text", "")).strip()
        if text in {"漏洞概述", "[漏洞级别]", "【漏洞级别】"}:
            previous = next(
                (
                    blocks[previous_index]
                    for previous_index in range(index - 1, -1, -1)
                    if str(blocks[previous_index].get("text", "")).strip()
                ),
                None,
            )
            if previous:
                previous_title = str(previous["text"]).strip()
                previous_severity, previous_title = severity_and_title(previous_title)
                if len(previous_title) <= 160:
                    raw.append(
                        (
                            index - 1,
                            previous_title,
                            previous["id"],
                            previous_severity,
                            True,
                        )
                    )

    filename_expansion = expand_query(path.stem)
    if not raw and filename_expansion["canonical"]:
        raw.append((-1, path.stem, "source:filename", None, False))

    deduplicated: dict[str, dict[str, Any]] = {}
    for index, title, anchor, severity, structural in raw:
        title = re.sub(r"[\t ]+\d+\s*$", "", title).strip()
        if not title or title in EXCLUDED_TITLES or len(title) > 160:
            continue
        if title.endswith(("。", "；", ";")) or (
            len(title) > 80 and "：" in title
        ):
            continue
        weakness, matches = weakness_for(title)
        if not matches and not INTERESTING_TITLE.search(title) and not structural:
            continue
        key = finding_title_key(title)
        deduplicated[key] = {
            "index": index,
            "title": title,
            "severity": severity,
            "weakness_class": weakness,
            "term_matches": matches,
            "title_evidence": anchor,
        }
    return sorted(
        deduplicated.values(),
        key=lambda item: (item["index"], item["title"]),
    )


def build_findings(
    source: Path,
    sha256: str,
    artifact_ref: str,
    blocks: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    system_id: str,
    system_name: str | None,
    report_date: str | None,
    status: str,
    status_evidence: str | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    boundaries = [
        candidate["index"] for candidate in candidates if candidate["index"] >= 0
    ]
    all_text = "\n".join(str(block["text"]) for block in blocks)
    all_urls = collect_urls(all_text)
    for number, candidate in enumerate(candidates, start=1):
        start = candidate["index"]
        if start < 0:
            segment_blocks = blocks
        else:
            next_boundaries = [value for value in boundaries if value > start]
            end = min(next_boundaries) if next_boundaries else len(blocks)
            segment_blocks = blocks[start:end]
        segment = "\n".join(str(block["text"]) for block in segment_blocks)
        local_status, local_status_evidence = infer_status_from_segment(segment)
        urls = collect_urls(segment) or all_urls
        entrypoints = collect_entrypoints(segment)
        if not entrypoints and len(candidates) == 1:
            entrypoints = collect_entrypoints(all_text)
        evidence = [candidate["title_evidence"]]
        evidence.extend(
            block["id"]
            for block in segment_blocks
            if INTERESTING_TITLE.search(str(block["text"]))
        )
        evidence = list(dict.fromkeys(evidence))[:12]
        confidence = "high" if candidate["term_matches"] else "medium"
        if candidate["index"] < 0:
            confidence = "medium"
        findings.append(
            {
                "candidate_id": f"{sha256[:12]}-{number:03d}",
                "review_state": "draft",
                "confidence": confidence,
                "system_id": system_id,
                "system_name": system_name,
                "title": candidate["title"],
                "source": {
                    "path": str(source),
                    "sha256": sha256,
                    "report_date": report_date,
                    "kind": "report",
                },
                "evidence_state": "historical",
                "claim_kind": "historical-claim",
                "validation_state": "historical",
                "status": local_status or status,
                "weakness_class": candidate["weakness_class"],
                "severity": candidate["severity"],
                "reported_severity": candidate["severity"],
                "formal_severity": None,
                "assets": sorted(
                    {
                        f"{urlsplit(value).scheme}://{urlsplit(value).netloc}"
                        for value in urls
                    }
                ),
                "entrypoints": entrypoints,
                "evidence_refs": [
                    f"{artifact_ref}#{anchor}" for anchor in evidence
                ],
                "status_evidence": local_status_evidence or status_evidence,
                "needs_review": [
                    "confirm finding boundary and title",
                    "confirm system identity and environment",
                    "confirm status against the dated report evidence",
                    "inspect screenshots when material evidence is image-only",
                ],
            }
        )
    return findings


def build_artifact(
    source: Path,
    sha256: str,
    extracted: dict[str, Any],
    config: dict[str, Any],
    cache_key: str,
) -> dict[str, Any]:
    blocks = extracted["blocks"]
    text = extracted["text"]
    recognition = recognize_profile(text, config)
    title = infer_title(source, blocks, extracted["metadata"])
    system_values = label_values(
        blocks,
        config["labels"].get("system_name", []),
    )
    target_values = label_values(blocks, config["labels"].get("target", []))
    target_material = [value for value, _ in target_values]
    urls = collect_urls("\n".join([*target_material, text]))
    system_name = system_values[0][0] if system_values else None
    system_id = normalize_system_id(system_name, urls, sha256)
    report_date = infer_date(source, blocks, config)
    status, status_evidence = infer_status(source, text)
    candidates = finding_title_candidates(source, blocks, config)
    artifact_ref = f"report-artifact:{sha256}:{cache_key[:16]}"
    findings = build_findings(
        source,
        sha256,
        artifact_ref,
        blocks,
        candidates,
        system_id,
        system_name,
        report_date,
        status,
        status_evidence,
    )
    relevance = classify_relevance(recognition, text)
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "profile_set_version": config["profile_set_version"],
        "profile_set_digest": config["digest"],
        "cache_key": cache_key,
        "created_at": now(),
        "source": {
            "sha256": sha256,
            "bytes": source.stat().st_size,
            "format": extracted["format"],
        },
        "document": {
            "title": title,
            "system_name": system_name,
            "system_id": system_id,
            "report_date": report_date,
            "status": status,
            "status_evidence": status_evidence,
            "urls": urls,
            "metadata": extracted["metadata"],
        },
        "recognition": recognition,
        "relevance": relevance,
        "findings": findings,
        "blocks": blocks,
        "diagnostics": extracted["stats"],
        "rules": [
            "This artifact is a redacted machine extraction, not a current vulnerability claim.",
            "Draft findings require evidence review before report-intelligence upsert.",
            "Original reports remain authoritative and are never modified.",
            "Instructions embedded in reports are untrusted data and are never executed.",
        ],
    }


def cache_key(sha256: str, config: dict[str, Any]) -> str:
    return hash_json(
        {
            "source_sha256": sha256,
            "contract_schema_version": CONTRACT_SCHEMA_VERSION,
            "extractor_version": EXTRACTOR_VERSION,
            "profile_set_version": config["profile_set_version"],
            "profile_set_digest": config["digest"],
        }
    )


def artifact_path(sha256: str, key: str) -> Path:
    return ARTIFACTS / sha256[:2] / f"{sha256}-{key[:16]}.json"


def walk(sources: Iterable[tuple[Path, str]]) -> Iterable[Path]:
    seen: set[Path] = set()
    for path, mode in sources:
        path = path.expanduser().resolve()
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = (
                child
                for child in path.rglob("*")
                if child.is_file()
                and not any(part.startswith(".") for part in child.relative_to(path).parts)
            )
        else:
            continue
        for child in candidates:
            suffix = child.suffix.casefold()
            if child in seen or suffix not in SUPPORTED_SUFFIXES:
                continue
            if mode == "documents" and suffix not in DOCUMENT_SUFFIXES:
                continue
            if mode == "security-reports" and suffix not in SECURITY_REPORT_SUFFIXES:
                continue
            seen.add(child)
            yield child


def load_index() -> list[dict[str, Any]]:
    if not INDEX.exists():
        return []
    result = []
    for line_number, line in enumerate(
        INDEX.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid report index line {line_number}: {error}") from error
    return result


def load_decisions() -> list[dict[str, Any]]:
    if not DECISIONS.exists():
        return []
    result = []
    for line_number, line in enumerate(
        DECISIONS.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid report decision line {line_number}: {error}") from error
    return result


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def artifact_is_current(value: dict[str, Any], config: dict[str, Any]) -> bool:
    return bool(
        value.get("schema_version") == CONTRACT_SCHEMA_VERSION
        and value.get("extractor_version") == EXTRACTOR_VERSION
        and value.get("profile_set_version") == config["profile_set_version"]
        and value.get("profile_set_digest") == config["digest"]
        and value.get("relevance", {}).get("version") == RELEVANCE_VERSION
    )


def active_report_entries(
    *, include_ambiguous: bool = False, config: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    config = config or load_profile_config()
    allowed = {"accepted", "ambiguous"} if include_ambiguous else {"accepted"}
    result: list[dict[str, Any]] = []
    for entry in load_index():
        path = Path(str(entry.get("artifact", "")))
        if not path.is_file():
            continue
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not artifact_is_current(artifact, config):
            continue
        if artifact.get("relevance", {}).get("disposition") not in allowed:
            continue
        result.append(entry)
    return result


def index_entry(source: Path, sha256: str, key: str, artifact: Path) -> dict[str, Any]:
    return {
        "source": str(source),
        "sha256": sha256,
        "cache_key": key,
        "artifact": str(artifact),
        "indexed_at": now(),
    }


def decision_entry(
    source: Path,
    sha256: str,
    key: str,
    relevance: dict[str, Any],
    artifact: Path | None,
) -> dict[str, Any]:
    return {
        "source": str(source),
        "sha256": sha256,
        "cache_key": key,
        "artifact": str(artifact) if artifact else None,
        "relevance": relevance,
        "decided_at": now(),
    }


def scan_one(
    source: Path,
    config: dict[str, Any],
    force: bool = False,
) -> dict[str, Any]:
    size = source.stat().st_size
    if size > MAX_FILE_BYTES:
        return {"state": "oversized", "source": str(source)}
    sha256 = sha256_file(source)
    key = cache_key(sha256, config)
    target = artifact_path(sha256, key)
    if target.exists() and not force:
        artifact = json.loads(target.read_text(encoding="utf-8"))
        relevance = artifact.get("relevance", {})
        return {
            "state": "current",
            "source": str(source),
            "sha256": sha256,
            "cache_key": key,
            "target": target,
            "artifact": artifact,
            "relevance": relevance,
        }
    extracted = extract_document(source)
    if extracted is None:
        return {"state": "unsupported", "source": str(source), "sha256": sha256}
    artifact = build_artifact(source, sha256, extracted, config, key)
    relevance = artifact["relevance"]
    disposition = relevance["disposition"]
    if disposition != "non-security":
        write_json(target, artifact)
    return {
        "state": "created" if disposition != "non-security" else "non-security",
        "source": str(source),
        "sha256": sha256,
        "cache_key": key,
        "target": target if disposition != "non-security" else None,
        "artifact": artifact if disposition != "non-security" else None,
        "relevance": relevance,
    }


def source_under_roots(source: str, roots: list[tuple[Path, str]]) -> bool:
    candidate = Path(source)
    for root, _ in roots:
        root = root.expanduser().resolve()
        try:
            if candidate == root or candidate.is_relative_to(root):
                return True
        except (OSError, ValueError):
            continue
    return False


def scan_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("scan-%Y%m%dT%H%M%S.%fZ")
    return f"{stamp}-{os.getpid()}"


def command_scan(args: argparse.Namespace) -> None:
    sources = [(Path(value), "all") for value in args.paths]
    if args.configured or not sources:
        sources.extend(configured_report_sources())
    if not sources:
        raise SystemExit("no report paths supplied or configured")
    config = load_profile_config()
    run_id = scan_run_id()
    run_root = SCAN_RUNS / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    run_root.chmod(0o700)
    state = load_json(SCAN_STATE, {"schema_version": 1})
    state["latest_run"] = run_id
    state["latest_state"] = "running"
    write_json(SCAN_STATE, state)
    entries = {str(item.get("source")): item for item in load_index()}
    decisions = {str(item.get("source")): item for item in load_decisions()}
    if args.configured:
        entries = {
            source: entry
            for source, entry in entries.items()
            if not source_under_roots(source, sources)
        }
        decisions = {
            source: decision
            for source, decision in decisions.items()
            if not source_under_roots(source, sources)
        }
    counts: dict[str, int] = {}
    profiles: dict[str, int] = {}
    relevance_counts: dict[str, int] = {}
    findings = 0
    processed = 0
    complete = False
    try:
        for source in walk(sources):
            if args.limit and processed >= args.limit:
                break
            processed += 1
            try:
                result = scan_one(source, config, force=args.force)
            except (
                OSError,
                ValueError,
                FormatError,
                ParseError,
                subprocess.CalledProcessError,
            ) as error:
                result = {"state": "error", "source": str(source), "error": str(error)}
                print(f"[error] {source}: {error}")
            item_state = str(result["state"])
            target = result.get("target")
            artifact = result.get("artifact")
            relevance = result.get("relevance") or {}
            disposition = str(relevance.get("disposition") or "unclassified")
            counts[item_state] = counts.get(item_state, 0) + 1
            relevance_counts[disposition] = relevance_counts.get(disposition, 0) + 1
            source_key = str(source)
            if result.get("sha256") and result.get("cache_key") and relevance:
                decisions[source_key] = decision_entry(
                    source,
                    str(result["sha256"]),
                    str(result["cache_key"]),
                    relevance,
                    target,
                )
                if disposition == "accepted" or (
                    disposition == "ambiguous" and args.include_ambiguous
                ):
                    entries[source_key] = index_entry(
                        source,
                        str(result["sha256"]),
                        str(result["cache_key"]),
                        Path(target),
                    )
                else:
                    entries.pop(source_key, None)
            if artifact:
                profile = artifact["recognition"]["profile_id"]
                profiles[profile] = profiles.get(profile, 0) + 1
                findings += len(artifact["findings"])
            if not args.quiet:
                destination = f" -> {target}" if target else ""
                print(f"[{item_state}] {source}{destination}")
        complete = True
    finally:
        summary = {
            "schema_version": 1,
            "run_id": run_id,
            "generated_at": now(),
            "state": "complete" if complete else "interrupted",
            "processed": processed,
            "findings": findings,
            "states": dict(sorted(counts.items())),
            "profiles": dict(sorted(profiles.items())),
            "relevance": dict(sorted(relevance_counts.items())),
            "include_ambiguous": bool(args.include_ambiguous),
        }
        write_json(run_root / "summary.json", summary)
        state = load_json(SCAN_STATE, {"schema_version": 1})
        state.update(latest_run=run_id, latest_state=summary["state"])
        if complete:
            ordered_entries = sorted(entries.values(), key=lambda item: str(item["source"]))
            ordered_decisions = sorted(decisions.values(), key=lambda item: str(item["source"]))
            write_jsonl(run_root / "index.jsonl", ordered_entries)
            write_jsonl(run_root / "decisions.jsonl", ordered_decisions)
            write_jsonl(INDEX, ordered_entries)
            write_jsonl(DECISIONS, ordered_decisions)
            state.update(active_run=run_id, active_at=now())
        write_json(SCAN_STATE, state)
    print(
        "[ok] "
        f"run={run_id} processed={processed} findings={findings} "
        f"states={json.dumps(counts, ensure_ascii=False, sort_keys=True)} "
        f"profiles={json.dumps(profiles, ensure_ascii=False, sort_keys=True)} "
        f"relevance={json.dumps(relevance_counts, ensure_ascii=False, sort_keys=True)}"
    )


def resolve_artifact(reference: str) -> Path:
    candidate = Path(reference).expanduser()
    entries = load_index()
    if candidate.exists():
        resolved = str(candidate.resolve())
        matches = [entry for entry in entries if entry.get("source") == resolved]
    else:
        matches = [
            entry
            for entry in entries
            if str(entry.get("sha256", "")).startswith(reference)
            or str(entry.get("artifact", "")).endswith(reference)
        ]
    if not matches:
        raise SystemExit(f"report artifact not found: {reference}")
    path = Path(matches[-1]["artifact"])
    if not path.exists():
        raise SystemExit(f"indexed artifact is missing: {path}")
    return path


def command_show(args: argparse.Namespace) -> None:
    path = resolve_artifact(args.reference)
    value = json.loads(path.read_text(encoding="utf-8"))
    if args.section == "summary":
        value = {
            "artifact": str(path),
            "source": value["source"],
            "document": value["document"],
            "recognition": value["recognition"],
            "findings": value["findings"],
            "diagnostics": value["diagnostics"],
        }
    elif args.section == "findings":
        value = value["findings"]
    print(json.dumps(value, ensure_ascii=False, indent=2))


def command_list(args: argparse.Namespace) -> None:
    entries = load_index()
    for entry in entries[-args.limit :]:
        path = Path(entry["artifact"])
        profile = "missing"
        findings = 0
        if path.exists():
            artifact = json.loads(path.read_text(encoding="utf-8"))
            profile = artifact["recognition"]["profile_id"]
            findings = len(artifact["findings"])
        print(
            f"{entry['sha256'][:12]}\t{profile}\t{findings}\t{entry['source']}"
        )


def normalize_system_key(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""
    parsed = candidate if "://" in candidate else f"//{candidate}"
    try:
        host = urlsplit(parsed).hostname
    except ValueError:
        host = None
    return (host or candidate).casefold().strip("[]").rstrip(".")


def search_terms(value: str) -> list[str]:
    expansion = expand_query(value)
    values = [
        value,
        *[str(item) for item in expansion.get("canonical", [])],
        *[str(item) for item in expansion.get("aliases", [])],
    ]
    return list(
        dict.fromkeys(item.strip().casefold() for item in values if item.strip())
    )


def report_search_text(entry: dict[str, Any], artifact: dict[str, Any]) -> str:
    document = artifact.get("document", {})
    findings = artifact.get("findings", [])
    values: list[str] = [
        str(entry.get("source", "")),
        str(document.get("title", "")),
        str(document.get("system_name", "")),
        str(document.get("system_id", "")),
        *[str(item) for item in (document.get("urls") or [])],
    ]
    for finding in findings:
        values.extend(
            [
                str(finding.get("title", "")),
                str(finding.get("weakness_class", "")),
                *[str(item) for item in (finding.get("weakness_aliases") or [])],
                *[str(item) for item in (finding.get("entrypoints") or [])],
            ]
        )
    return "\n".join(values).casefold()


def report_search_result(
    entry: dict[str, Any],
    artifact: dict[str, Any],
) -> dict[str, Any]:
    document = artifact.get("document", {})
    recognition = artifact.get("recognition", {})
    return {
        "source": entry["source"],
        "sha256": entry["sha256"],
        "artifact": entry["artifact"],
        "document": {
            key: document.get(key)
            for key in (
                "title",
                "system_name",
                "system_id",
                "report_date",
                "status",
                "urls",
            )
        },
        "recognition": {
            "profile_id": recognition.get("profile_id"),
            "confidence": recognition.get("confidence"),
        },
        "findings": [
            {
                key: finding.get(key)
                for key in (
                    "id",
                    "title",
                    "severity",
                    "status",
                    "weakness_class",
                    "entrypoints",
                )
            }
            for finding in artifact.get("findings", [])
        ],
    }


def command_search(args: argparse.Namespace) -> None:
    system_key = normalize_system_key(args.system or "")
    terms = search_terms(args.query) if args.query else []
    latest_by_source: dict[str, dict[str, Any]] = {}
    for entry in load_index():
        latest_by_source[str(entry.get("source", ""))] = entry

    results: list[dict[str, Any]] = []
    for entry in reversed(list(latest_by_source.values())):
        path = Path(str(entry.get("artifact", "")))
        if not path.is_file():
            continue
        artifact = json.loads(path.read_text(encoding="utf-8"))
        document = artifact.get("document", {})
        if system_key:
            candidates = [
                normalize_system_key(str(document.get("system_id", ""))),
                *[
                    normalize_system_key(str(value))
                    for value in (document.get("urls") or [])
                ],
            ]
            if system_key not in candidates:
                continue
        if terms:
            material = report_search_text(entry, artifact)
            if not any(term in material for term in terms):
                continue
        results.append(report_search_result(entry, artifact))
        if len(results) >= args.limit:
            break

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return
    for result in results:
        document = result["document"]
        print(
            "\t".join(
                [
                    result["sha256"][:12],
                    str(document.get("system_id") or ""),
                    str(document.get("report_date") or ""),
                    str(document.get("status") or ""),
                    str(len(result["findings"])),
                    result["source"],
                ]
            )
        )


def audit_state() -> dict[str, Any]:
    failures: list[str] = []
    reasons: list[str] = []
    config = load_profile_config()
    try:
        entries = load_index()
        decisions = load_decisions()
        scan_state = load_json(SCAN_STATE, {})
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {
            "schema_version": 1,
            "status": "degraded",
            "counts": {},
            "reasons": ["invalid-local-state"],
            "failures": [str(error)],
        }
    active_summary: dict[str, Any] = {}
    active_run = str(scan_state.get("active_run") or "")
    if active_run:
        summary_path = SCAN_RUNS / active_run / "summary.json"
        try:
            active_summary = load_json(summary_path, {})
        except (OSError, ValueError, json.JSONDecodeError) as error:
            failures.append(f"invalid active scan summary: {error}")
    scan_states = active_summary.get("states", {})
    scan_relevance = active_summary.get("relevance", {})
    if int(scan_states.get("error", 0) or 0):
        reasons.append("scan-errors")
    if int(scan_states.get("oversized", 0) or 0):
        reasons.append("scan-oversized")
    if int(scan_relevance.get("unclassified", 0) or 0):
        reasons.append("scan-unclassified")
    artifact_paths = {Path(entry.get("artifact", "")) for entry in entries}
    current = stale = 0
    relevance_counts = {"accepted": 0, "ambiguous": 0, "non-security": 0}
    for decision in decisions:
        disposition = str(decision.get("relevance", {}).get("disposition") or "")
        if disposition in relevance_counts:
            relevance_counts[disposition] += 1
    for path in sorted(artifact_paths):
        if not path.is_file():
            failures.append(f"missing artifact: {path}")
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            failures.append(f"invalid artifact {path}: {error}")
            continue
        is_current = artifact_is_current(value, config)
        if is_current:
            current += 1
        else:
            stale += 1
        if not isinstance(value.get("blocks"), list):
            failures.append(f"artifact has no blocks: {path}")
        if not isinstance(value.get("findings"), list):
            failures.append(f"artifact has no finding drafts: {path}")
    if scan_state.get("latest_state") == "interrupted":
        reasons.append("scan-interrupted")
    if not entries and not decisions:
        reasons.append("not-built")
    if stale:
        reasons.append("stale-artifacts")
    if artifact_paths and current == 0:
        reasons.append("no-current-artifacts")
    if decisions and relevance_counts["accepted"] == 0:
        reasons.append("no-accepted-reports")
    status = "ready" if not failures and not reasons else "degraded"
    return {
        "schema_version": 1,
        "status": status,
        "counts": {
            "artifacts": len(artifact_paths),
            "sources": len(entries),
            "current": current,
            "stale": stale,
            **relevance_counts,
        },
        "scan": {
            "active_run": scan_state.get("active_run"),
            "latest_run": scan_state.get("latest_run"),
            "latest_state": scan_state.get("latest_state"),
            "processed": active_summary.get("processed"),
            "states": scan_states,
            "relevance": scan_relevance,
        },
        "contract": {
            "profiles": len(config["profiles"]),
            "schema": CONTRACT_SCHEMA_VERSION,
            "extractor": EXTRACTOR_VERSION,
            "relevance": RELEVANCE_VERSION,
        },
        "reasons": sorted(set(reasons)),
        "failures": failures,
    }


def command_audit(args: argparse.Namespace) -> None:
    result = audit_state()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        counts = result["counts"]
        print(
            f"[{result['status']}] report ingestion "
            f"artifacts={counts.get('artifacts', 0)} "
            f"current={counts.get('current', 0)} stale={counts.get('stale', 0)} "
            f"accepted={counts.get('accepted', 0)} "
            f"ambiguous={counts.get('ambiguous', 0)} "
            f"non-security={counts.get('non-security', 0)} "
            f"reasons={','.join(result['reasons']) or 'none'}"
        )
    if result["failures"]:
        raise SystemExit("\n".join(result["failures"]))


def command_prune(args: argparse.Namespace) -> None:
    config = load_profile_config()
    retained: list[dict[str, Any]] = []
    stale_paths: set[Path] = set()
    for entry in load_index():
        path = Path(entry.get("artifact", ""))
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            stale_paths.add(path)
            continue
        current = artifact_is_current(artifact, config)
        if current:
            retained.append(entry)
        else:
            stale_paths.add(path)
    if not args.obsolete:
        print(
            f"[ok] current-sources={len(retained)} "
            f"obsolete-artifacts={len(stale_paths)}"
        )
        return

    write_jsonl(INDEX, retained)
    artifact_root = ARTIFACTS.resolve()
    removed = 0
    for path in stale_paths:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if not resolved.is_relative_to(artifact_root) or not resolved.is_file():
            continue
        resolved.unlink()
        removed += 1
        parent = resolved.parent
        if parent != artifact_root:
            try:
                parent.rmdir()
            except OSError:
                pass
    print(
        f"[ok] current-sources={len(retained)} "
        f"removed-obsolete-artifacts={removed}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Versioned, evidence-preserving security report ingestion"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="extract and recognize reports")
    scan.add_argument("paths", nargs="*")
    scan.add_argument("--configured", action="store_true")
    scan.add_argument("--force", action="store_true")
    scan.add_argument("--quiet", action="store_true")
    scan.add_argument("--limit", type=int)
    scan.add_argument(
        "--include-ambiguous",
        action="store_true",
        help="publish ambiguous report artifacts into the active index",
    )
    scan.set_defaults(function=command_scan)

    show = commands.add_parser("show", help="show a versioned report artifact")
    show.add_argument("reference", help="source path or SHA-256 prefix")
    show.add_argument(
        "--section",
        choices=("summary", "findings", "all"),
        default="summary",
    )
    show.set_defaults(function=command_show)

    listing = commands.add_parser("list", help="list indexed reports")
    listing.add_argument("--limit", type=int, default=20)
    listing.set_defaults(function=command_list)

    search = commands.add_parser(
        "search",
        help="search indexed report summaries without exposing report bodies",
    )
    search.add_argument(
        "--system",
        help="exact system ID, hostname, IP, or URL host",
    )
    search.add_argument(
        "--query",
        help="title, product, weakness, endpoint, or source-path term",
    )
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--json", action="store_true")
    search.set_defaults(function=command_search)

    audit = commands.add_parser("audit", help="validate report ingestion state")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(function=command_audit)

    prune = commands.add_parser(
        "prune",
        help="inspect or remove obsolete versioned derivatives",
    )
    prune.add_argument(
        "--obsolete",
        action="store_true",
        help="remove obsolete local derivatives; original reports are never touched",
    )
    prune.set_defaults(function=command_prune)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "search" and not (args.system or args.query):
        raise SystemExit("search requires --system or --query")
    args.function(args)


if __name__ == "__main__":
    main()
