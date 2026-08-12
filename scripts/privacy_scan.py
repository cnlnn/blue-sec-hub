#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    "",
    ".json",
    ".jsonl",
    ".lock",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIP_PARTS = {".git", ".ci-state", ".venv", ".work", "__pycache__", ".pytest_cache"}
PATTERNS = {
    "github-access-token": re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    "cloud-access-key": re.compile(r"\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b"),
    "bearer-token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "local-user-path": re.compile(
        r"/(?:home|Users)/[^/\s]+/(?:Documents|Downloads|\.codex|security-evidence)/|"
        r"/opt/" r"tools/|[A-Za-z]:\\Users\\[^\\\s]+\\"
    ),
    "organization-identity": re.compile(
        r"(?:客户|厂商|防守|建设|运营)" r"单位\s*[:：]\s*\S{2,}|"
        r"\S{2,}(?:有限责任" r"公司|股份有限" r"公司|集团" r"公司)"
    ),
}


def scan_repository(root: Path = ROOT) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.casefold() not in TEXT_SUFFIXES or path.stat().st_size > 5 * 1024 * 1024:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(root)}: {label}")
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan repository text for secrets and local evidence paths")
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    args = parser.parse_args()
    findings = scan_repository(args.root.resolve())
    if findings:
        raise SystemExit("\n".join(findings))
    print("[ok] repository privacy scan")


if __name__ == "__main__":
    main()
