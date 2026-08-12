#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


CACHE_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_CACHE",
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "blue-sec-hub",
    )
)
DESTINATION = CACHE_ROOT / "upstreams" / "payloads-all-the-things"
SOURCE_URL = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
LOCAL_SEED = (
    Path(os.environ["BLUE_SEC_PAYLOADS_SOURCE"]).expanduser()
    if os.environ.get("BLUE_SEC_PAYLOADS_SOURCE")
    else None
)
SCHEMA_VERSION = 1
CATALOG_VERSION = "1.0.0"
MAX_FILE_BYTES = 25 * 1024 * 1024
TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".csv", ".json", ".yaml", ".yml",
    ".xml", ".xsl", ".html", ".htm", ".php", ".py", ".js", ".sh",
    ".ps1", ".java", ".cs", ".rb", ".go", ".ini", ".conf", "",
}
LINE_PAYLOAD_SUFFIXES = {".txt", ".csv"}
ACTIVE_SUFFIXES = {
    ".php", ".py", ".js", ".sh", ".ps1", ".java", ".cs", ".rb",
    ".go", ".exe", ".dll", ".so", ".jar", ".class", ".apk", ".ipa",
}
BLOCKED_SIGNAL = re.compile(
    r"(?:reverse.?shell|bind.?shell|web.?shell|mimikatz|credential.?dump|"
    r"/etc/(?:shadow|passwd)|rm\s+-rf|drop\s+table|shutdown|reboot|"
    r"fork.?bomb|denial.?of.?service|billion.?laughs|cobalt.?strike|"
    r"meterpreter|powershell.*download|wget\s+https?://|curl\s+https?://|"
    r"nc\s+-e|/dev/tcp|certutil.*urlcache)",
    re.I,
)
OOB_SIGNAL = re.compile(
    r"(?:burpcollaborator|interactsh|oast|webhook|callback|dnslog|"
    r"ATTACKER[_ .-]?(?:IP|HOST|DOMAIN|SERVER)|YOUR[_ .-]?(?:IP|HOST|DOMAIN)|"
    r"localhost|127\.0\.0\.1|169\.254\.|file://|gopher://|dict://)",
    re.I,
)
WRITE_SIGNAL = re.compile(
    r"(?:upload|write.?file|file.?write|delete|remove|overwrite|create.?file|"
    r"state.?change|csrf|race.?condition|mass.?assignment)",
    re.I,
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hash_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def stable_id(prefix: str, value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return f"{prefix}-{hash_bytes(raw)[:16]}"


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


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
    with path.open("w", encoding="utf-8") as handle:
        for value in values:
            handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
    if os.name != "nt":
        path.chmod(0o600)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    values = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def git(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def source_metadata(source: Path) -> dict[str, str]:
    try:
        commit = git("rev-parse", "HEAD", cwd=source)
        commit_date = git("show", "-s", "--format=%cI", "HEAD", cwd=source)
        url = git("remote", "get-url", "origin", cwd=source)
    except (OSError, subprocess.CalledProcessError):
        commit = hash_bytes(str(source.resolve()).encode())
        commit_date = now()
        url = str(source.resolve())
    return {"url": url, "commit": commit, "commit_date": commit_date}


def family_for(relative: Path) -> str:
    value = " ".join(relative.parts).casefold()
    mappings = (
        ("identity-session.response-differential", r"account takeover|brute force rate limit"),
        ("identity-session.authentication", r"insecure randomness"),
        ("identity-session.cross-origin-csrf", r"csrf|cross.site request forgery"),
        ("authorization.object-level", r"idor|insecure direct object"),
        ("authorization.property-level", r"mass assignment"),
        ("identity-session.oauth-sso", r"oauth|saml|openid"),
        ("identity-session.session-token", r"jwt|json web token|session"),
        ("injection.sql-nosql-orm", r"sql injection|nosql injection|orm"),
        ("injection.command-code-template", r"command injection|code injection|ssti|template injection"),
        ("injection.command-code-template", r"server side include injection"),
        ("injection.xml-ldap-xpath", r"ldap injection|xpath injection|xslt injection"),
        ("injection.request-header-log", r"crlf injection|log injection"),
        ("injection.prototype-mass-assignment", r"prototype pollution|type juggling"),
        ("browser-content.xss-dom-richtext", r"xss injection|cross.site scripting"),
        ("browser-content.xss-dom-richtext", r"css injection|dom clobbering"),
        ("browser-content.redirect-scheme", r"open redirect|url redirect"),
        ("browser-content.redirect-scheme", r"tabnabbing"),
        ("browser-content.postmessage-framing", r"clickjacking|xs.leak"),
        ("server-side-processing.ssrf-webhook-proxy", r"ssrf|server side request forgery"),
        ("server-side-processing.ssrf-webhook-proxy", r"dns rebinding"),
        ("server-side-processing.xxe-parser", r"xxe|xml external"),
        ("server-side-processing.deserialization-template", r"deserialization|pickle|yaml|java rmi"),
        ("server-side-processing.converter-background-job", r"headless browser|latex injection|regular expression"),
        ("server-side-processing.unsafe-api-consumption", r"prompt injection"),
        ("files-data-export.upload-validation", r"upload insecure files|file upload"),
        ("files-data-export.path-read-download", r"directory traversal|path traversal|file inclusion"),
        ("files-data-export.archive-extraction", r"zip slip|archive"),
        ("files-data-export.import-export-formula", r"csv injection"),
        ("api-protocol.edge-backend-normalization", r"request smuggling|http parameter pollution|waf bypass"),
        ("api-protocol.graphql", r"graphql"),
        ("api-protocol.websocket-sse-soap", r"web sockets|websocket|soap"),
        ("business-logic.race-concurrency", r"race condition"),
        ("business-logic.replay-idempotency", r"replay|idempot"),
        ("business-logic.lifecycle-integrity", r"business logic errors"),
        ("business-logic.quota-resource-abuse", r"denial of service"),
        ("platform-exposure.headers-cache-cors", r"cors|cache poisoning|cache deception|host header"),
        ("platform-exposure.headers-cache-cors", r"reverse proxy misconfigurations|virtual hosts"),
        ("platform-exposure.debug-admin-docs", r"debug|swagger|api key leaks|git|source code management|insecure management interface"),
        ("platform-exposure.dependencies-supply-chain", r"dependency confusion|cve exploits"),
        ("authorization.property-level", r"external variable modification|hidden parameters"),
    )
    for family, pattern in mappings:
        if re.search(pattern, value, re.I):
            return family
    if relative.parts and relative.parts[0] in {
        "Methodology and Resources",
        "Google Web Toolkit",
        "_LEARNING_AND_SOCIALS",
        "_template_vuln",
    }:
        return "reference-only"
    if len(relative.parts) == 1:
        return "reference-only"
    return "unmapped"


def injection_points(text: str, relative: Path) -> list[str]:
    value = f"{relative} {text}".casefold()
    result = []
    for name, pattern in (
        ("header", r"header|user-agent|referer|host:"),
        ("cookie", r"cookie"),
        ("query", r"query|url parameter|get parameter"),
        ("body", r"body|json|form|post parameter"),
        ("path", r"path|url segment|traversal"),
        ("file", r"file|upload|archive|multipart"),
        ("xml", r"xml|soap|xpath|xslt"),
    ):
        if re.search(pattern, value, re.I):
            result.append(name)
    return result or ["unspecified"]


def placeholders(value: str) -> list[str]:
    matches = re.findall(
        r"(?:<[^<>\n]{1,80}>|\{[^{}\n]{1,80}\}|\b(?:ATTACKER|YOUR|TARGET|CALLBACK)[A-Z0-9_.-]*\b)",
        value,
        re.I,
    )
    return sorted(set(matches))[:100]


def safety_for(value: str, relative: Path, family: str) -> tuple[str, list[str]]:
    combined = f"{relative} {value}"
    if BLOCKED_SIGNAL.search(combined) or relative.suffix.casefold() in ACTIVE_SUFFIXES:
        return "blocked", ["command-persistence-exfiltration-or-active-content"]
    if OOB_SIGNAL.search(combined):
        return "needs-agent", ["controlled-oob-or-network-destination-required"]
    if WRITE_SIGNAL.search(combined) or family in {
        "identity-session.cross-origin-csrf",
        "files-data-export.upload-validation",
        "business-logic.race-concurrency",
    }:
        return "needs-agent", ["self-owned-reversible-context-required"]
    if family in {
        "injection.sql-nosql-orm",
        "injection.xml-ldap-xpath",
        "browser-content.xss-dom-richtext",
        "api-protocol.edge-backend-normalization",
        "platform-exposure.headers-cache-cors",
    } and len(value.encode("utf-8")) <= 4096:
        return "safe-auto-candidate", ["requires-read-only-shape-and-curated-approval"]
    return "needs-agent", ["no-approved-deterministic-safety-policy"]


def oracle_for(family: str) -> dict[str, list[str]]:
    if family.startswith("authorization."):
        return {
            "positive": ["normal baseline and one identity or object variable prove access outside the allowed boundary"],
            "negative": ["HTTP success, handler reachability and nonexistent objects are insufficient"],
        }
    if family.startswith("injection.") or family.startswith("server-side-processing."):
        return {
            "positive": ["repeatable single-variable parser differential with concrete security impact"],
            "negative": ["generic errors, timing noise, reflection and WAF responses are insufficient"],
        }
    return {
        "positive": ["repeatable single-variable behavior crosses the evidenced security boundary"],
        "negative": ["status code or payload acceptance without impact is insufficient"],
    }


def markdown_records(relative: Path, text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    family = family_for(relative)
    techniques = []
    payloads = []
    heading = relative.stem
    fence_language = ""
    fence_lines: list[str] | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        heading_match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if heading_match and fence_lines is None:
            heading = normalize_text(heading_match.group(2).strip("# `"))
            technique_id = stable_id("patt-technique", [family, str(relative), heading.casefold()])
            techniques.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "technique_id": technique_id,
                    "family": family,
                    "title": heading[:240],
                    "source_ref": f"{relative}:{line_number}",
                    "injection_points": injection_points(heading, relative),
                }
            )
            continue
        fence = re.match(r"^\s*```([^`]*)$", line)
        if fence:
            if fence_lines is None:
                fence_language = fence.group(1).strip()[:40]
                fence_lines = []
            else:
                template = "\n".join(fence_lines).strip()
                if template:
                    payloads.append(payload_record(relative, heading, family, template, fence_language))
                fence_lines = None
                fence_language = ""
            continue
        if fence_lines is not None:
            fence_lines.append(line)
    if fence_lines:
        template = "\n".join(fence_lines).strip()
        if template:
            payloads.append(payload_record(relative, heading, family, template, fence_language))
    return techniques, payloads


def payload_record(
    relative: Path,
    heading: str,
    family: str,
    template: str,
    language: str = "",
) -> dict[str, Any]:
    normalized = normalize_text(template)
    payload_id = stable_id("patt-payload", [family, normalized])
    safety, reasons = safety_for(template, relative, family)
    return {
        "schema_version": SCHEMA_VERSION,
        "payload_id": payload_id,
        "technique_ref": stable_id("patt-technique", [family, str(relative), heading.casefold()]),
        "family": family,
        "title": heading[:240],
        "template": template,
        "template_sha256": hash_bytes(template.encode("utf-8")),
        "language": language,
        "placeholders": placeholders(template),
        "injection_points": injection_points(f"{heading} {template[:500]}", relative),
        "suggested_policy": safety,
        "approved_for_automatic_execution": False,
        "policy_reasons": reasons,
        "oracle": oracle_for(family),
        "source_refs": [str(relative)],
    }


def harden_tree(root: Path) -> None:
    if os.name == "nt":
        return
    for path in root.rglob("*"):
        try:
            path.chmod(0o700 if path.is_dir() else 0o600)
        except OSError:
            continue
    root.chmod(0o700)


def ignore_unsafe_copy(directory: str, names: list[str]) -> set[str]:
    root = Path(directory)
    return {
        name
        for name in names
        if name == ".git" or (root / name).is_symlink()
    }


def record_hash(value: dict[str, Any]) -> str:
    filtered = {key: item for key, item in value.items() if key not in {"source_refs"}}
    return hash_bytes(json.dumps(filtered, ensure_ascii=False, sort_keys=True).encode())


def change_manifest(
    previous: list[dict[str, Any]],
    current: list[dict[str, Any]],
    key: str,
) -> dict[str, list[str]]:
    old = {str(item[key]): record_hash(item) for item in previous if item.get(key)}
    new = {str(item[key]): record_hash(item) for item in current if item.get(key)}
    return {
        "added": sorted(set(new) - set(old)),
        "changed": sorted(identifier for identifier in set(new) & set(old) if new[identifier] != old[identifier]),
        "removed": sorted(set(old) - set(new)),
    }


def build_catalog(
    source: Path,
    destination: Path,
    metadata: dict[str, str] | None = None,
    previous_destination: Path | None = None,
) -> dict[str, Any]:
    metadata = metadata or source_metadata(source)
    previous_destination = previous_destination or destination
    previous_payloads = load_jsonl(previous_destination / "payloads.jsonl")
    previous_techniques = load_jsonl(previous_destination / "techniques.jsonl")
    raw_destination = destination / "raw"
    if raw_destination.exists():
        shutil.rmtree(raw_destination)
    shutil.copytree(source, raw_destination, ignore=ignore_unsafe_copy)
    ledgers = []
    techniques: dict[str, dict[str, Any]] = {}
    payloads: dict[str, dict[str, Any]] = {}
    statuses: Counter[str] = Counter()
    families: Counter[str] = Counter()
    for path in sorted(source.rglob("*")):
        if ".git" in path.parts:
            continue
        relative = path.relative_to(source)
        if path.is_symlink():
            ledgers.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "source_ref": str(relative),
                    "size": 0,
                    "sha256": None,
                    "status": "unsupported-symlink",
                    "reason": "symlink-target-not-copied-or-indexed",
                }
            )
            statuses["unsupported-symlink"] += 1
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        suffix = path.suffix.casefold()
        record = {
            "schema_version": SCHEMA_VERSION,
            "source_ref": str(relative),
            "size": size,
            "sha256": hash_file(path),
            "status": None,
            "reason": None,
        }
        file_techniques: list[dict[str, Any]] = []
        file_payloads: list[dict[str, Any]] = []
        try:
            if size > MAX_FILE_BYTES:
                record.update(status="oversized", reason="file-size-limit")
            elif suffix not in TEXT_SUFFIXES:
                record.update(status="cataloged-binary", reason="raw-cache-only-never-executed")
            else:
                text = path.read_text(encoding="utf-8", errors="replace")
                if suffix in {".md", ".markdown"}:
                    file_techniques, file_payloads = markdown_records(relative, text)
                    record.update(status="parsed", reason="markdown-techniques-and-code-blocks")
                elif suffix in LINE_PAYLOAD_SUFFIXES:
                    family = family_for(relative)
                    heading = relative.stem
                    for line in text.splitlines():
                        value = line.strip()
                        if not value or value.startswith(("#", "//", ";")):
                            continue
                        file_payloads.append(payload_record(relative, heading, family, value))
                    file_techniques.append(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "technique_id": stable_id("patt-technique", [family, str(relative), heading.casefold()]),
                            "family": family,
                            "title": heading[:240],
                            "source_ref": str(relative),
                            "injection_points": injection_points(heading, relative),
                        }
                    )
                    record.update(status="parsed", reason="line-payloads")
                else:
                    family = family_for(relative)
                    heading = relative.stem
                    file_techniques.append(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "technique_id": stable_id("patt-technique", [family, str(relative), heading.casefold()]),
                            "family": family,
                            "title": heading[:240],
                            "source_ref": str(relative),
                            "injection_points": injection_points(heading, relative),
                            "active_content": suffix in ACTIVE_SUFFIXES,
                        }
                    )
                    if text.strip():
                        file_payloads.append(payload_record(relative, heading, family, text, suffix.lstrip(".")))
                    record.update(
                        status="cataloged-active" if suffix in ACTIVE_SUFFIXES else "parsed",
                        reason="never-executed-as-file" if suffix in ACTIVE_SUFFIXES else "structured-text",
                    )
        except OSError as error:
            record.update(status="error", reason=type(error).__name__)
        statuses[str(record["status"])] += 1
        ledgers.append(record)
        for technique in file_techniques:
            techniques[technique["technique_id"]] = technique
            families[technique["family"]] += 1
        for payload in file_payloads:
            existing = payloads.get(payload["payload_id"])
            if existing:
                existing["source_refs"] = sorted(set(existing["source_refs"] + payload["source_refs"]))
                if existing["suggested_policy"] != "blocked" and payload["suggested_policy"] == "blocked":
                    existing["suggested_policy"] = "blocked"
                    existing["policy_reasons"] = sorted(set(existing["policy_reasons"] + payload["policy_reasons"]))
            else:
                payloads[payload["payload_id"]] = payload
    technique_values = sorted(techniques.values(), key=lambda item: item["technique_id"])
    payload_values = sorted(payloads.values(), key=lambda item: item["payload_id"])
    write_jsonl(destination / "source-ledger.jsonl", ledgers)
    write_jsonl(destination / "techniques.jsonl", technique_values)
    write_jsonl(destination / "payloads.jsonl", payload_values)
    changes = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now(),
        "source_commit": metadata["commit"],
        "techniques": change_manifest(previous_techniques, technique_values, "technique_id"),
        "payloads": change_manifest(previous_payloads, payload_values, "payload_id"),
        "approved_semantics_changed": False,
    }
    atomic_json(destination / "change-manifest.json", changes)
    policies = Counter(item["suggested_policy"] for item in payload_values)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "catalog_version": CATALOG_VERSION,
        "generated_at": now(),
        "source": metadata,
        "files": len(ledgers),
        "source_statuses": dict(sorted(statuses.items())),
        "techniques": len(technique_values),
        "payloads": len(payload_values),
        "families": dict(sorted(families.items())),
        "suggested_policies": dict(sorted(policies.items())),
        "automatic_execution_approved": 0,
        "state": "complete",
    }
    atomic_json(destination / "summary.json", summary)
    license_path = source / "LICENSE"
    if license_path.exists():
        shutil.copy2(license_path, destination / "LICENSE")
    harden_tree(destination)
    return summary


def sync_catalog(source: Path | None, destination: Path, force: bool = False) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="payload-catalog-", dir=destination.parent) as temporary:
        temporary_root = Path(temporary)
        if source is None:
            source = temporary_root / "repository"
            subprocess.run(
                ["git", "clone", "--depth", "1", SOURCE_URL, str(source)],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        source = source.expanduser().resolve()
        if not source.is_dir():
            raise SystemExit(f"payload source not found: {source}")
        metadata = source_metadata(source)
        current = load_json(destination / "summary.json", {})
        if not force and current.get("source", {}).get("commit") == metadata["commit"]:
            return current
        stage = temporary_root / "stage"
        stage.mkdir()
        summary = build_catalog(source, stage, metadata, previous_destination=destination)
        previous = destination.with_name(destination.name + ".previous")
        if previous.exists():
            shutil.rmtree(previous)
        if destination.exists():
            destination.replace(previous)
        try:
            stage.replace(destination)
        except Exception:
            if destination.exists():
                shutil.rmtree(destination)
            if previous.exists():
                previous.replace(destination)
            raise
        if previous.exists():
            shutil.rmtree(previous)
        return summary


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def command_sync(args: argparse.Namespace) -> None:
    source = args.source
    if source is None and args.prefer_local and LOCAL_SEED and LOCAL_SEED.is_dir():
        source = LOCAL_SEED
    summary = sync_catalog(source, args.destination, args.force)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def command_status(args: argparse.Namespace) -> None:
    summary = load_json(args.destination / "summary.json", {})
    if not summary:
        raise SystemExit("payload catalog is not synchronized")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def command_diff(args: argparse.Namespace) -> None:
    manifest = load_json(args.destination / "change-manifest.json", {})
    if not manifest:
        raise SystemExit("payload catalog change manifest is unavailable")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


def command_search(args: argparse.Namespace) -> None:
    pattern = re.compile(re.escape(args.query), re.I)
    matches = []
    for name in ("techniques.jsonl", "payloads.jsonl"):
        for value in load_jsonl(args.destination / name):
            haystack = json.dumps(
                {key: item for key, item in value.items() if key != "template"},
                ensure_ascii=False,
            )
            if pattern.search(haystack) or pattern.search(str(value.get("template", ""))):
                matches.append(value)
                if len(matches) >= args.limit:
                    break
        if len(matches) >= args.limit:
            break
    for value in matches:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Index PayloadsAllTheThings without executing payloads")
    parser.add_argument("--destination", type=Path, default=DESTINATION)
    commands = parser.add_subparsers(dest="command", required=True)
    sync = commands.add_parser("sync")
    sync.add_argument("--source", type=Path)
    sync.add_argument("--prefer-local", action="store_true")
    sync.add_argument("--force", action="store_true")
    sync.set_defaults(function=command_sync)
    status = commands.add_parser("status")
    status.set_defaults(function=command_status)
    difference = commands.add_parser("diff")
    difference.set_defaults(function=command_diff)
    search = commands.add_parser("search")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=50)
    search.set_defaults(function=command_search)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
